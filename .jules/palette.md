## 2024-05-24 - [Command Line Feedback]
**Learning:** In CLI/TUI applications using `if/elif` chains for command handling, lack of an explicit `else` or default handler leaves users confused when they mistype commands, as there is no visual feedback that the input was processed but rejected.
**Action:** Always implement a default "Unknown command" handler in command loops to provide immediate feedback to the user, ensuring they know the system is responsive but the command was invalid.
