# Contributing to SSH Brute Force Detection Script

Thank you for your interest in contributing to this project! We welcome contributions from the community and are grateful for any help you can provide.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/ssh-bruteforce-detector.git
   cd ssh-bruteforce-detector
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites
- Python 3.6 or higher
- Git
- Basic understanding of log analysis and cybersecurity concepts

### Environment Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Code Quality Tools
```bash
# Run linting
flake8 bruteforce_detector.py

# Run type checking
mypy bruteforce_detector.py

# Format code
black bruteforce_detector.py

# Run tests (if available)
pytest tests/
```

## Contributing Guidelines

### Code Style
- Follow **PEP 8** Python style guide
- Use **type hints** where appropriate
- Write **clear, descriptive variable names**
- Add **docstrings** for functions and classes
- Keep line length under **88 characters** (Black formatter standard)

### Documentation
- Update **README.md** if adding new features
- Add **inline comments** for complex logic
- Include **usage examples** for new functionality
- Update **command-line help text** if adding new options

### Testing
- Write **unit tests** for new features
- Test with **various log formats** and edge cases
- Verify **performance** with large log files
- Test **error handling** and edge cases

### Security Considerations
- **Never commit** real authentication logs
- **Sanitize** any example data
- Consider **performance implications** of regex patterns
- **Validate** all user inputs
- **Handle errors gracefully**

## Pull Request Process

1. **Update documentation** reflecting the changes
2. **Add tests** that prove your fix/feature works
3. **Run all quality checks**:
   ```bash
   flake8 bruteforce_detector.py
   mypy bruteforce_detector.py
   black --check bruteforce_detector.py
   pytest  # if tests exist
   ```
4. **Update the README.md** with details of changes if needed
5. **Create a pull request** with:
   - Clear description of changes
   - Reference to any related issues
   - Screenshots/examples if applicable

### Pull Request Title Format
```
type(scope): brief description

Examples:
feat(detection): add geolocation lookup for IP addresses
fix(parser): handle malformed timestamp entries
docs(readme): update installation instructions
refactor(core): optimize regex pattern matching
```

## Reporting Bugs

### Before Submitting a Bug Report
- **Check existing issues** to avoid duplicates
- **Test with the latest version**
- **Try with sample data** to isolate the issue

### Bug Report Template
```markdown
## Bug Description
Brief description of the bug

## Steps to Reproduce
1. Command used: `python3 bruteforce_detector.py ...`
2. Input: describe log format or attach sample (anonymized)
3. Expected behavior
4. Actual behavior

## Environment
- OS: [e.g., Ubuntu 20.04]
- Python version: [e.g., 3.8.5]
- Script version: [e.g., 1.0.0]

## Additional Context
- Error messages
- Stack traces
- Sample log entries (anonymized)
```

## Suggesting Enhancements

### Enhancement Categories
- **New detection patterns** for different attack types
- **Performance improvements** for large log files
- **Additional output formats** (XML, database export, etc.)
- **Integration features** with security tools
- **User interface improvements**
- **Documentation enhancements**

### Enhancement Request Template
```markdown
## Enhancement Description
Clear description of the proposed feature

## Use Case
Why would this feature be useful?

## Proposed Implementation
Brief technical approach (if you have ideas)

## Alternatives Considered
Other solutions you've considered

## Additional Context
Screenshots, examples, or references
```

## Development Workflow

### Branching Strategy
- `main` - Production-ready code
- `develop` - Integration branch for features
- `feature/*` - Feature development branches
- `hotfix/*` - Critical bug fixes

### Commit Message Format
```
type(scope): subject line (max 50 chars)

Longer explanation if needed. Wrap at 72 characters.
Include motivation for change and contrast with previous behavior.

- Bullet points are okay
- Use present tense: "fix bug" not "fixed bug"
- Reference issues: "Closes #123"
```

### Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding tests
- `chore`: Maintenance tasks

## Recognition

Contributors will be recognized in:
- **README.md** acknowledgments section
- **CHANGELOG.md** for significant contributions
- **GitHub releases** notes

## Questions?

- **GitHub Discussions**: For general questions
- **GitHub Issues**: For bug reports and feature requests
- **Email**: security@yourproject.com for security-related issues

Thank you for contributing to the cybersecurity community! 🛡️
