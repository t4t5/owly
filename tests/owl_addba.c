/* owl -A: an ADDBA Request to us is recognised (RX_ADDBA, its fields in
 * state->addba), and answered with an ADDBA Response that accepts it:
 * immediate Block Ack, the requested TID, no A-MSDU, a window of at most 64
 * (patches/owl-10-addba-accept.patch). Without -A, or addressed to someone
 * else, the request is ignored as before. Built against OWL's sources under
 * AddressSanitizer by test_owl_addba.py. */
#include <stdio.h>
#include <string.h>

#include "rx.h"
#include "tx.h"
#include "state.h"
#include "ieee80211.h"

static const struct ether_addr self = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}};
static const struct ether_addr peer = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};
static const struct ether_addr other = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}};

static int failed;

#define EXPECT(cond, ...) do { if (!(cond)) { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); failed = 1; } } while (0)

/* Category, action, dialog token, parameter set, timeout, starting sequence. */
static int request(uint8_t *out, uint8_t token, uint16_t params, uint16_t timeout) {
	const uint8_t body[9] = {IEEE80211_CATEGORY_BACK, IEEE80211_ACTION_ADDBA_REQ, token,
	                         params & 0xff, params >> 8, timeout & 0xff, timeout >> 8, 0x10, 0x00};
	memcpy(out, body, sizeof(body));
	return sizeof(body);
}

static uint16_t params_of(int amsdu, int tid, int size) {
	return (uint16_t) ((amsdu ? 1 : 0) | 0x0002 | (tid << 2) | (size << 6));
}

static int receive(struct awdl_state *state, const struct ether_addr *to, const uint8_t *raw, int len) {
	const struct buf *frame = buf_new_const(raw, len);
	int result = awdl_rx_action(frame, -40, clock_time_us(), &peer, to, state);
	buf_free(frame);
	return result;
}

static void check_response(const char *what, uint16_t asked, int want_tid, int want_size) {
	struct awdl_state state;
	struct ieee80211_state ieee = {0};
	uint8_t raw[16], out[256];
	const uint8_t *hdr, *body;
	int len, result, rt_len;
	uint16_t params;

	awdl_init_state(&state, "test", &self, CHAN_NULL, clock_time_us());
	state.filter_rssi = 0;
	state.accept_addba = 1;
	result = receive(&state, &self, raw, request(raw, 0x5a, asked, 300));
	EXPECT(result == RX_ADDBA, "%s: result %d, expected RX_ADDBA", what, result);
	EXPECT(!memcmp(&state.addba.peer, &peer, sizeof(peer)), "%s: wrong peer recorded", what);
	EXPECT(state.addba.token == 0x5a && state.addba.params == asked && state.addba.timeout == 300,
	       "%s: recorded token %u params %#x timeout %u", what, state.addba.token, state.addba.params,
	       state.addba.timeout);

	len = awdl_init_addba_response(out, &state, &ieee);
	rt_len = out[2] | out[3] << 8;
	hdr = out + rt_len;
	body = hdr + sizeof(struct ieee80211_hdr);
	EXPECT(len == rt_len + (int) sizeof(struct ieee80211_hdr) + 9, "%s: length %d", what, len);
	EXPECT(hdr[0] == 0xd0 && hdr[1] == 0x00, "%s: frame control %02x %02x, expected an action frame",
	       what, hdr[0], hdr[1]);
	EXPECT(!memcmp(hdr + 4, &peer, 6) && !memcmp(hdr + 10, &self, 6), "%s: addresses", what);
	EXPECT(body[0] == IEEE80211_CATEGORY_BACK && body[1] == IEEE80211_ACTION_ADDBA_RESP,
	       "%s: category %u action %u", what, body[0], body[1]);
	EXPECT(body[2] == 0x5a, "%s: dialog token %#x", what, body[2]);
	EXPECT(body[3] == 0 && body[4] == 0, "%s: status %u", what, body[3] | body[4] << 8);
	params = (uint16_t) (body[5] | body[6] << 8);
	EXPECT((params & 1) == 0, "%s: A-MSDU in A-MPDU offered", what);
	EXPECT(params & 2, "%s: not immediate Block Ack", what);
	EXPECT(((params >> 2) & 0xf) == want_tid, "%s: TID %u, expected %d", what, (params >> 2) & 0xf, want_tid);
	EXPECT((params >> 6) == want_size, "%s: window %u, expected %d", what, params >> 6, want_size);
	EXPECT((body[7] | body[8] << 8) == 300, "%s: timeout not echoed", what);
	awdl_peers_free(state.peers.peers);
}

int main(void) {
	struct awdl_state state;
	uint8_t raw[16];
	int result;

	check_response("as an iPhone asks (TID 5, 64)", params_of(1, 5, 64), 5, 64);
	check_response("a window over 64 is capped", params_of(0, 0, 256), 0, 64);
	check_response("no window given means 64", params_of(0, 6, 0), 6, 64);
	check_response("a smaller window is kept", params_of(0, 2, 32), 2, 32);

	/* Without -A the request is ignored, as before. */
	awdl_init_state(&state, "test", &self, CHAN_NULL, clock_time_us());
	state.filter_rssi = 0;
	result = receive(&state, &self, raw, request(raw, 1, params_of(0, 0, 64), 0));
	EXPECT(result == RX_IGNORE, "without -A: result %d, expected RX_IGNORE", result);

	/* Addressed to another station: not ours to accept. */
	state.accept_addba = 1;
	result = receive(&state, &other, raw, request(raw, 1, params_of(0, 0, 64), 0));
	EXPECT(result == RX_IGNORE, "to another station: result %d, expected RX_IGNORE", result);

	/* The starting sequence number is kept for the reorder buffer. */
	result = receive(&state, &self, raw, request(raw, 1, params_of(0, 0, 64), 0));
	EXPECT(result == RX_ADDBA && state.addba.ssn == 1, "starting sequence number %u, expected 1", state.addba.ssn);

	/* DELBA: the peer ends the session for TID 6. */
	{
		const uint8_t delba[6] = {IEEE80211_CATEGORY_BACK, IEEE80211_ACTION_DELBA, 0x00, 0x60, 0x01, 0x00};
		memcpy(raw, delba, sizeof(delba));
		result = receive(&state, &self, raw, sizeof(delba));
		EXPECT(result == RX_DELBA && state.addba.tid == 6, "DELBA: result %d TID %u", result, state.addba.tid);
	}

	/* Too short to be a request: falls through to the AWDL parser, which ignores it. */
	result = receive(&state, &self, raw, 5);
	EXPECT(result == RX_IGNORE, "truncated: result %d, expected RX_IGNORE", result);
	awdl_peers_free(state.peers.peers);

	return failed;
}
