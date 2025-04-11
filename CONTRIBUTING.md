# Contributing to Gödel

Thank you for your interest in contributing to Gödel! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project.

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
- Check the issue tracker to see if the issue has already been reported.
- Try to reproduce the issue with the latest version.

When submitting a bug report, please include:
- A clear and descriptive title.
- Detailed steps to reproduce the issue.
- Expected behavior and what actually happens.
- Any relevant logs, screenshots, or code samples.

### Suggesting Features

Feature suggestions are welcome. Please provide:
- A clear and descriptive title.
- A detailed description of the proposed feature.
- Any relevant context or examples.

### Pull Requests

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with clear, descriptive messages.
4. Push your branch to your fork.
5. Submit a pull request to the main repository.

#### Pull Request Guidelines

- Follow the existing code style.
- Add tests for new features and ensure all tests pass.
- Update documentation if necessary.
- Keep pull requests focused on a single issue or feature.

## Development Setup

1. Clone your fork of the repository.
2. Set up the required dependencies:
   ```
   go mod download
   ```
3. Build the project:
   ```
   ./build.sh
   ```

## Testing

Run tests using:
```
go test ./...
```

## Coding Standards

- Follow Go's standard formatting guidelines (use `go fmt`).
- Write clear, self-explanatory code and add comments where necessary.
- Keep functions and methods small and focused on a single task.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).