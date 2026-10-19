/* Receive reordering for a Block Ack session (patches/owl-12-rx-reorder.patch):
 * frames come out in sequence order, gaps are waited for until they fill,
 * the window moves past them, a Block Ack Request gives them up or they time
 * out; old and duplicate frames are dropped, and nothing leaks. Built against
 * OWL's sources under AddressSanitizer by test_owl_reorder.py. */
#include <stdio.h>
#include <string.h>

#include "reorder.h"

static const struct ether_addr peer = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};
static const struct ether_addr other = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}};

static int out[256];
static int nout;
static int failed;

/* Each test frame carries its sequence number (and A-MSDU index) as data. */
static struct buf *frame(int sn, int part) {
	struct buf *b = buf_new_owned(2);
	uint8_t *d = (uint8_t *) buf_data(b);
	d[0] = (uint8_t) (sn & 0xff);
	d[1] = (uint8_t) (((sn >> 8) & 0x0f) | (part << 4));
	return b;
}

static void deliver(struct buf *b, void *arg) {
	const uint8_t *d = buf_data(b);
	(void) arg;
	out[nout++] = d[0] | (d[1] & 0x0f) << 8;
	buf_free(b);
}

static int rx(struct reorder_state *r, const struct ether_addr *who, int sn, uint64_t now) {
	struct buf *f = frame(sn, 0);
	int taken = reorder_rx(r, who, 0, (uint16_t) sn, &f, 1, now, deliver, NULL);
	if (!taken)
		buf_free(f);
	return taken;
}

static void expect(const char *what, const int *want, int n) {
	int ok = nout == n && !memcmp(out, want, sizeof(int) * n);
	if (!ok) {
		fprintf(stderr, "%s: delivered", what);
		for (int i = 0; i < nout; i++)
			fprintf(stderr, " %d", out[i]);
		fprintf(stderr, ", expected");
		for (int i = 0; i < n; i++)
			fprintf(stderr, " %d", want[i]);
		fputc('\n', stderr);
		failed = 1;
	}
	nout = 0;
}

#define EXPECT(what, ...) do { const int w[] = {__VA_ARGS__}; expect(what, w, sizeof(w) / sizeof(w[0])); } while (0)
#define EXPECT_NONE(what) expect(what, NULL, 0)

int main(void) {
	struct reorder_state r;
	uint64_t t = 1000000;

	reorder_init(&r);
	if (rx(&r, &peer, 1, t)) {
		fprintf(stderr, "no session: frame taken\n");
		failed = 1;
	}

	/* In order: straight through. */
	reorder_start(&r, &peer, 0, 64, 100, deliver, NULL);
	for (int sn = 100; sn < 104; sn++)
		rx(&r, &peer, sn, t);
	EXPECT("in order", 100, 101, 102, 103);

	/* A gap is waited for, and filling it releases what queued behind it. */
	rx(&r, &peer, 105, t);
	rx(&r, &peer, 106, t);
	EXPECT_NONE("behind a gap");
	rx(&r, &peer, 106, t); /* duplicate */
	rx(&r, &peer, 104, t);
	EXPECT("gap filled", 104, 105, 106);
	rx(&r, &peer, 102, t); /* old */
	EXPECT_NONE("old frame dropped");

	/* A frame past the window moves it: what is held before the new start
	 * goes out, the gap is skipped. */
	reorder_start(&r, &peer, 0, 8, 0, deliver, NULL);
	rx(&r, &peer, 1, t);
	rx(&r, &peer, 9, t);
	EXPECT("window moved past a gap", 1);
	rx(&r, &peer, 2, t);
	EXPECT("then in order", 2);

	/* Timeout: held frames go out once the oldest has waited long enough.
	 * (Restarting first delivers 9, still held from the window above.) */
	reorder_start(&r, &peer, 0, 64, 20, deliver, NULL);
	EXPECT("restart delivers what the old window held", 9);
	rx(&r, &peer, 20, t);
	rx(&r, &peer, 22, t + 10000);
	rx(&r, &peer, 23, t + 20000);
	EXPECT("before timeout", 20);
	reorder_expire(&r, t + 50000, REORDER_TIMEOUT_US, deliver, NULL);
	EXPECT_NONE("not yet");
	reorder_expire(&r, t + 10000 + REORDER_TIMEOUT_US, REORDER_TIMEOUT_US, deliver, NULL);
	EXPECT("timed out", 22, 23);
	rx(&r, &peer, 21, t + 200000); /* too late */
	EXPECT_NONE("late frame dropped");

	/* A Block Ack Request gives up the gap at once. */
	reorder_start(&r, &peer, 0, 64, 30, deliver, NULL);
	rx(&r, &peer, 31, t);
	rx(&r, &peer, 32, t);
	reorder_bar(&r, &peer, 0, 31, deliver, NULL);
	EXPECT("Block Ack Request", 31, 32);
	reorder_bar(&r, &peer, 0, 20, deliver, NULL); /* behind: ignored */
	rx(&r, &peer, 33, t);
	EXPECT("after it", 33);

	/* Sequence numbers wrap at 4096. */
	reorder_start(&r, &peer, 0, 64, 4094, deliver, NULL);
	rx(&r, &peer, 4095, t);
	rx(&r, &peer, 0, t);
	rx(&r, &peer, 4094, t);
	rx(&r, &peer, 1, t);
	EXPECT("wraparound", 4094, 4095, 0, 1);

	/* An A-MSDU's frames share a sequence number and stay together, in order. */
	{
		struct buf *f[3] = {frame(2, 0), frame(2, 1), frame(2, 2)};
		rx(&r, &peer, 3, t);
		reorder_rx(&r, &peer, 0, 2, f, 3, t, deliver, NULL);
		EXPECT("A-MSDU", 2, 2, 2, 3);
	}

	/* Restarting delivers what the old session held; so does stopping. */
	rx(&r, &peer, 6, t);
	reorder_start(&r, &peer, 0, 64, 50, deliver, NULL);
	EXPECT("restart flushes", 6);
	rx(&r, &peer, 52, t);
	reorder_stop(&r, &peer, 0, deliver, NULL);
	EXPECT("stop flushes", 52);
	if (rx(&r, &peer, 53, t)) {
		fprintf(stderr, "after stop: frame taken\n");
		failed = 1;
	}

	/* Another peer and another TID are separate sessions. */
	reorder_start(&r, &peer, 0, 64, 0, deliver, NULL);
	reorder_start(&r, &other, 0, 64, 500, deliver, NULL);
	rx(&r, &other, 501, t);
	rx(&r, &peer, 0, t);
	EXPECT("other peer's gap doesn't hold this one", 0);
	{
		struct buf *f = frame(7, 0);
		if (reorder_rx(&r, &peer, 5, 7, &f, 1, t, deliver, NULL)) {
			fprintf(stderr, "TID without a session: frame taken\n");
			failed = 1;
		} else {
			buf_free(f);
		}
	}

	/* Held frames are freed on teardown (LeakSanitizer checks). */
	rx(&r, &peer, 9, t);
	reorder_free(&r);
	return failed;
}
