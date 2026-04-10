# Use of AI in Development

This project makes use of AI-assisted development tools, primarily ChatGPT and Claude, as part of the development workflow.

## Role of AI

AI has been used as a supporting tool, not as a replacement for engineering judgment. Its contributions include:

- Assisting with CLI design and output formatting
- Helping write and refine tests
- Acting as a sparring partner for design and programming decisions
- Supporting implementation of specific components (e.g. RBAC, audit features)
- Providing secondary reviews, including security-related considerations

## Human Ownership

All core aspects of the system are designed and owned by humans, including:

- Overall architecture and system design
- Security model and critical decision-making
- Final implementation choices

Every piece of AI-generated code has been:

- Reviewed
- Validated
- Modified or rejected where necessary

**No generated code is accepted blindly.**

## Security Considerations

Security-sensitive components receive additional scrutiny:

- Manual human review is always performed
- AI has been used as an additional review layer, not as the primary authority


## Philosophy

We view AI as a productivity tool, comparable to a compiler, linter, or IDE — useful when applied with understanding and intent.

There is a clear distinction between:

 - AI-assisted engineering (used in this project), and
 - Unsupervised “vibe coding”, where code is generated without sufficient understanding or validation

This project firmly follows the former approach.