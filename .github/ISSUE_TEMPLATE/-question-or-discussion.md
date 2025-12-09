---
name: " Question or Discussion"
about: Ask a question or start a discussion
title: ''
labels: ''
assignees: ''

---

title: "[QUESTION] "
labels: ["question"]
body:
  - type: markdown
    attributes:
      value: |
        Have a question? Let's discuss!
  
  - type: textarea
    id: question
    attributes:
      label: Your Question
      description: What would you like to know?
    validations:
      required: true
  
  - type: textarea
    id: context
    attributes:
      label: Context
      description: Any additional context?
  
  - type: input
    id: version
    attributes:
      label: wshawk Version
      placeholder: "2.0.x"
