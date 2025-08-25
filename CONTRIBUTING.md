# Contributing to Himacrypt

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Contributors](https://img.shields.io/github/contributors/himalabs/himacrypt.svg)](https://github.com/himalabs/himacrypt/graphs/contributors)

Thank you for your interest in contributing to **Himacrypt**! We welcome all kinds of contributions — bug reports, feature suggestions, code changes, and documentation improvements.

Please read the guidelines below to ensure a smooth contribution process.

---

## 📜 Code of Conduct

By participating in this project, you agree to follow our [Code of Conduct](./CODE_OF_CONDUCT.md). Be respectful and constructive in all discussions.

---

## 🐞 Bug Reports

If you find a bug, please help us fix it by submitting an issue. When filing a bug report, include:

- A clear and descriptive title
- Steps to reproduce the problem
- Expected and actual behavior
- Screenshots or logs, if applicable
- Your environment (OS, Python version, etc.)

Check [existing issues](https://github.com/himalabs/himacrypt/issues) before reporting to avoid duplicates.

---

## 💡 Feature Requests

We're open to feature ideas! When suggesting a new feature:

- Explain the problem it solves
- Provide use cases or examples
- Propose a possible solution or implementation (optional)

Use the **Feature Request** template when opening an issue.

---

## 🛠️ How to Contribute

### 1. Fork the Repository

Click “Fork” in the upper right and clone your fork:

```bash
git clone https://github.com/himalabs/himacrypt.git
cd your-repo
```
### 2. Create a New Branch
```bash
git checkout -b feat/your-feature-name
```
### 3. Install Dependencies
```bash
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 4. Make Changes
- Follow the existing code style

- Write or update tests

- Run formatting and linting tools (e.g., `black`, `ruff`, etc.)

### 5. Commit Your Changes
Follow the commit message guidelines below.


### ✅ Commit Message Guidelines
We follow [Conventional Commits](https://www.conventionalcommits.org/)  to keep our git history clean and readable.

Format
```bash
<type>(optional scope): short description

[optional body]

[optional footer]
```

### Types
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, missing semi-colons, etc.)
- `refactor`: Code changes that neither fix a bug nor add a feature
- `test`: Adding or correcting tests
- `chore`: Maintenance tasks (build process, CI, etc.)


### Examples
```bash
feat(auth): add login endpoint with JWT support
fix(api): correct typo in response field name
docs(readme): update installation instructions
style: run black formatter on all modules
refactor(db): simplify query logic for performance
```

### 6. Push and Open a Pull Request
```bash
git push origin feat/your-feature-name
```
Then create a [Pull Request](https://github.com/himalabs/himacrypt/pulls) to the main branch. Fill out the PR template.

---

### 📃 License
By contributing, you agree that your contributions will be licensed under the same license as this project. See the LICENSE file for more details.

---

### 🙋 Need Help?
If you have any questions or need guidance, feel free to open an issue or contact a project maintainer.
Happy contributing! 🚀
