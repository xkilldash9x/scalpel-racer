# Gemini CLI Agent: Project Instructions for Scalpel Racer

## Project Overview

Scalpel Racer is an advanced race condition testing tool written in Go. It appears to operate as a transparent HTTP/HTTPS proxy to identify and exploit concurrency vulnerabilities in web applications by sending synchronized concurrent requests.

**Key Insight**: The architecture seems to center on **request capture -> modification -> concurrent replay** with different synchronization mechanisms for maximum timing precision. This document guides the Gemini CLI agent in understanding and contributing to this project.

## About Me: The Gemini CLI Agent

I am a non-interactive CLI agent specializing in software engineering tasks. My primary goal is to help you safely and efficiently. I will adhere strictly to the following mandates:

- **Conventions**: I will rigorously adhere to existing project conventions when reading or modifying code. I will analyze surrounding code, tests, and configuration first.
- **Style & Structure**: I will mimic the style (formatting, naming), structure, and architectural patterns of existing Go code in the project.
- **Idiomatic Changes**: My changes will integrate naturally and idiomatically with the existing Go codebase.
- **Proactiveness**: I will fulfill your requests thoroughly. This includes adding tests to ensure quality when adding features or fixing bugs.
- **Safety**: I will explain any commands that modify the file system before running them.

## How to Interact With Me

Provide clear, specific, and concise instructions. I work best when I have a clear goal.

- **For complex tasks** (e.g., "refactor the proxy logic," "investigate a bug," "add a new attack strategy"), I will start by using my `codebase_investigator` tool to build a deep understanding of the codebase.
- **For simple tasks** (e.g., "read file `main.go`," "find where `HTTPRequest` is defined"), I will use tools like `read_file` and `search_file_content`.

## My Workflow

I follow a structured approach to software development:

1.  **Understand & Strategize**: I first analyze your request and the codebase to form a plan. For complex tasks, I use `codebase_investigator`.
2.  **Plan**: I create a step-by-step plan, often using `write_todos` to track progress on complex tasks.
3.  **Implement**: I use my tools (`read_file`, `write_file`, `replace`, `run_shell_command`) to implement the changes.
4.  **Verify**: I verify my changes by running the project's tests and quality checks.

## Key Tools at My Disposal

- **`codebase_investigator`**: For deep, architectural analysis of the codebase.
- **`search_file_content`**: For fast, `ripgrep`-powered code search.
- **`read_file`, `write_file`, `replace`**: For file manipulation.
- **`run_shell_command`**: For executing shell commands like `go test`, `go build`, `gofmt`, etc.
- **`write_todos`**: For creating and managing a public task list for our work.

## Project-Specific Commands & Conventions

Based on the project structure, I will use the following standard Go commands.

### Running Tests
To run all tests and benchmarks:
```bash
go test -v ./...
```
To run tests with coverage:
```bash
go test -v -cover ./...
```

### Building the Project
To build the main application:
```bash
go build ./cmd/scalpel-racer
```

### Code Style
I will ensure all Go code is formatted according to `gofmt` before finalizing my changes.

## Architectural Components (Initial Analysis)

My initial analysis of the file structure suggests the following components:

- **`cmd/scalpel-racer`**: The main entry point of the application.
- **`internal/engine`**: Core logic for attack strategies and request synchronization.
- **`internal/proxy`**: The HTTP/HTTPS proxy implementation, including interception and certificate handling.
- **`internal/packet`**: Low-level packet manipulation, possibly for advanced synchronization techniques.
- **`internal/models`**: Data structures for requests, responses, and results.
- **`internal/ui`**: A terminal-based user interface, likely using the bubbletea library.

Please keep this file updated if there are specific conventions or details you want me to be aware of.