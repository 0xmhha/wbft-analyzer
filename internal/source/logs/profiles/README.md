# Pinned log profile data

`gstable@740526d03.json` is an unchanged copy of the generated public
profile in wbft-inspector main `a3521b1` (PR #32), generated from all 184
A-13 catalog locations in wbft-spec `1c91f50`. The profile generator and
semantic mapping are owned by inspector, not duplicated here. Input
metadata records the full SHA256 of this file. Changing phrases requires
regenerating the inspector profile and updating this pinned copy.

`LoadProfile("wbft")` uses `observe/logcat.BuildProfile()` from the pinned
WBFT module. Logs remain wall-clock observations and are not equivalent
to complete node event streams.
