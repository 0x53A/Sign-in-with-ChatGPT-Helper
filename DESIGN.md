# Visual pattern

Inspired by Idiosepius: instrument-like layout, monospace typography, tracked
uppercase section labels, sentence-case prose, hairline borders. Square corners
on every widget, panel and field. No gradients, drop shadows or pill buttons.

Native: dark violet field #130D20; surfaces #2B1E41; lines #694D8F; foreground
#EBE2FF; lavender accent #C1A5FF. Header, listener controls, request details and
status are vertically ordered in a centered, spacious column. Header: bold
“Login with OpenAI” with a small “HELPER” suffix. A checkbox, port and “Allow
Connections” label share a row, followed by Import and a divider. Incoming
requests each show the app, browser-verified origin, inline PIN field and arrow.
Never display the received PIN: only a field for the user to transcribe it.
Import is the approval action for a file request; its origin is only a claim.
Login replaces the list with Open in Browser and, beneath it, Copy Link to Clipboard.
Never launch a browser automatically. Completion shows Close, plus Save result for offline
handoff. Close returns to the listener. Keep explanatory prose in documentation.
No credential viewer or plaintext export.
Buttons follow Idiosepius interaction styling: lavender border on hover, violet
fill while pressed, and no expansion or movement between states. Set both egui
background fills when changing a state; buttons use weak_bg_fill.

Web: light aqua field #E9F7FA; almost-white inputs #F8FEFF; line #98C4CE;
foreground #153E4B; deep aqua action #176E82. Compact centered column, no cards
inside cards. Header: “Login with OpenAI” and small “DEMO”. Signed out: Connect to
helper and Download Offline Package. Reveal port/PIN during online connection,
or the result importer after downloading an offline package (restore it on reload).
Signed in: Login Success, Logout, then model, message and output. Hide login
choices while signed in and inference while signed out. Feedback stays in one status strip. Wrap controls
at narrow widths; preserve readable text and visible keyboard focus.

The example is a plain page. Only request packages can be downloaded from its UI;
private keys and tokens remain in browser memory/encrypted storage. Build evidence
is linked in the footer, without an installation/update flow.
