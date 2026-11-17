# JSON CLI interface

These opt-in options allow desktop frontends and scripts to use Owly without
parsing terminal formatting or answering its interactive prompt. They do not
change the AirDrop protocol, radio mode or privilege model.

Without `--json`, the existing human-readable output and interactive receiver
prompt remain the default. `--json` is supported by `browse`, `receive` and
`radio up`; this change does not add JSON output to `send`.

## Transport

Each event is one UTF-8 JSON object followed by a newline on stdout. Each line is
flushed immediately, including when stdout is a pipe. Diagnostic messages remain
on stderr. Names, URLs, reasons and paths are serialized as JSON strings, including
escaping embedded quotes and newlines. A stream reader should dispatch on `event`
and tolerate additional fields or unfamiliar events.

An output write/flush failure ends the JSON operation with an error. If radio
readiness cannot be written, the radio lease is released and the existing Wi-Fi
restoration path is run. Do not merge stderr into stdout when parsing events.

The `ready` event describes successful startup, not successful file delivery.
Transfer IDs and device IDs are different: receiver transfer `id` values are
numbers, whereas browse receiver `id` values are strings.

## Radio

```sh
owly radio up --json
```

After successful acquisition:

```json
{"event":"ready"}
```

Keep this process running while using the interface. Its existing Ctrl-C/SIGTERM
cleanup releases the radio lease. A failing acquisition produces no ready event;
use the exit status and stderr diagnostics. The process does not announce devices
or receive files by itself.

## Browsing

```sh
owly browse --json --seconds 15
```

Each distinct answering endpoint is listed as:

```json
{"event":"receiver","id":"0123456789ab","name":"Example iPhone","address":"[fe80::1%4]:8770"}
```

`id` is the receiver's service ID or AWDL address and can be passed to
`owly send --to ID -- FILES...`. `address` is the resolved scoped IPv6 endpoint;
it is not an argument to `--to`. Discovery remains limited by `--seconds`.
No receivers found means a successful empty stdout stream. There is no browse
ready or completion event; the process exit terminates the stream.

## Receiving

```sh
owly receive --json --dir "$HOME/Downloads"
```

The receiver emits `ready` after binding and completing its configured mDNS
registration. It retains the normal radio/interface setup requirements.

| Event | Fields | Meaning |
| --- | --- | --- |
| `ready` | none | Receiver startup completed. |
| `request` | `id`, `sender`, `items`, `timeout` | Sender asks for approval. `items` lists offered filenames or URLs. `timeout` is the receiver's approval timeout in seconds, currently 15. |
| `withdrawn` | `id` | The sender withdrew or the approval timer expired; remove the prompt. |
| `received` | `id`, `paths` | Transfer completed and files were committed to the destination. |
| `urls` | `id`, `urls` | Accepted links; they are displayed, never automatically opened. |
| `failed` | `id`, `reason` | Transfer failed. |

Example request:

```json
{"event":"request","id":7,"sender":"Example iPhone","items":["photo.jpg"],"timeout":15}
```

Write exactly one JSON object per stdin line to answer:

```json
{"id":7,"accept":true}
```

Use `false` to decline. `id` must be a non-negative integer and `accept` must
be a JSON boolean. Missing fields, unknown fields and malformed JSON are rejected
with a stderr diagnostic; the receiver continues waiting. Unknown, duplicate or
no-longer-pending IDs have no effect. Decisions do not produce acknowledgements;
accepting allows the transfer to proceed, and subsequent events report its result.
The `--accept` automatic-acceptance option conflicts with `--json`.

Multiple requests can be pending; associate each prompt with its own `id`.
Handle `withdrawn` to close expired prompts. `timeout` is the configured approval
window rather than a fresh deadline starting when a frontend renders its UI.
Discovery-only observations are not emitted in JSON mode.

Keep stdin open while waiting for transfers. EOF stops the receiver and drops
unanswered requests, which declines them. Ctrl-C also stops the receiver. After
an answer, the underlying driver owns transfer completion and cleanup. Output
write failures and input read errors also stop the JSON loop. Do not reuse IDs
between receiver processes; IDs are local to one process.

## Frontend lifecycle

Use separate pipes and argument arrays when launching commands. Hold the radio
process for the session, wait for its ready event, start the receiver, then use
browse and send as needed. Close the receiver's input and stop other frontend
children when shutting down; terminate the radio process through its normal
cleanup signal. Frontends do not need to run AirDrop processes as root.
