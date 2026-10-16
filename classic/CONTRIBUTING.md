# Contributing to HeartbeatGuard

Thank you for your interest in contributing to HeartbeatGuard! This document provides guidelines and information for contributors.

## 🎯 Project Overview

HeartbeatGuard is a security monitoring system designed specifically for OpenClaw AI agents. Our goal is to provide comprehensive, lightweight, and reliable security monitoring that integrates seamlessly with AI agent workflows.

## 🚀 Getting Started

### Development Setup

1. Fork the repository
2. Clone your fork:
```bash
git clone https://github.com/YOUR_USERNAME/heartbeat-guard.git
cd heartbeat-guard
```

3. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

4. Install development dependencies:
```bash
pip install -e ".[dev]"
```

5. Run tests to verify setup:
```bash
pytest tests/
```

## 📋 Development Guidelines

### Code Style

We use Black for code formatting and flake8 for linting:

```bash
# Format code
black heartbeat_guard/

# Check linting
flake8 heartbeat_guard/

# Type checking
mypy heartbeat_guard/
```

### Testing

- Write tests for all new functionality
- Maintain or improve test coverage
- Test on multiple Python versions (3.9+)

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=heartbeat_guard
```

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add SSL certificate expiration monitoring
fix: handle missing psutil dependency gracefully
docs: update README with new configuration options
test: add unit tests for skill scanner
```

## 🔧 Types of Contributions

### Security Checks
- New security monitoring capabilities
- Enhanced threat detection algorithms
- Performance optimizations

### Platform Support
- Support for additional operating systems
- Integration with new monitoring tools
- Cloud platform compatibility

### Documentation
- API documentation improvements
- Tutorial and guide creation
- Example configurations

### Bug Fixes
- Security vulnerability patches
- Performance improvements
- Compatibility fixes

## 📝 Contribution Process

### For Bug Reports

1. Check existing issues first
2. Use the bug report template
3. Include:
   - Operating system and version
   - Python version
   - HeartbeatGuard version
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### For Feature Requests

1. Check existing issues and discussions
2. Use the feature request template
3. Include:
   - Problem description
   - Proposed solution
   - Alternative solutions considered
   - Use cases and benefits

### For Code Contributions

1. Create an issue or comment on existing issue
2. Fork the repository
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Make your changes
5. Add tests and documentation
6. Ensure all tests pass
7. Create a pull request

## 🔒 Security Considerations

Since HeartbeatGuard is a security tool, please:

- Be extra careful with security-related changes
- Report security vulnerabilities privately to bsifflard@monomoystrategies.com
- Follow secure coding practices
- Consider the security implications of new features

## 📚 Resources

- [OpenClaw Documentation](https://openclaw.com/docs)
- [HeartbeatGuard Website](https://heartbeatguard.com)
- [API Documentation](https://heartbeatguard.com/api)

## 💬 Communication

- **Issues**: Use GitHub issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Email**: Contact bsifflard@monomoystrategies.com for private matters

## 📄 License

By contributing to HeartbeatGuard, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be:
- Listed in the CONTRIBUTORS.md file
- Credited in release notes
- Featured on the project website (with permission)

Thank you for helping make HeartbeatGuard better and more secure for the AI agent community! 🛡️