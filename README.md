
# 🔍 LogLens

> **Turn raw application logs into actionable engineering insights.**

### Built by Ashvitha Reddy

---

## 👩‍💻 About the Project

**LogLens** is a developer-focused log intelligence CLI built by **Ashvitha Reddy** to transform raw application logs into structured, actionable engineering insights.

Instead of treating logs as plain text, LogLens provides answers to practical observability questions:

- Which requests are failing?
- Which endpoints generate the most errors?
- Are response times increasing?
- Which endpoints are experiencing reliability issues?
- Did a change introduce application regressions?
- Are there unusual error or latency patterns?

What began as a simple log-analysis utility evolved into a structured CLI supporting parsing, statistical analysis, filtering, anomaly detection, health scoring, log comparison, automated testing, and HTML/JSON reporting.

---

## 🎯 Project Motivation

LogLens was developed to explore a practical **developer and DevOps workflow** for analyzing application behavior through logs.

Logs are often one of the first sources developers investigate when diagnosing application failures. LogLens focuses on transforming large amounts of raw log data into measurable metrics and structured insights, reducing the need for manual inspection.

### Key Objectives

- Build a practical command-line developer tool
- Understand real-world log processing and normalization
- Analyze application reliability using measurable metrics
- Identify abnormal error and latency patterns
- Compare application behavior across different log datasets
- Generate structured reports for further investigation
- Apply software engineering principles to a complete Python project
- Develop automated testing and maintainable project architecture

---

## 📚 Technical Concepts & Skills

The development of LogLens involved several practical software engineering and data analysis concepts.

### 🐍 Python Development

- Modular Python architecture
- Object-oriented programming
- Data models
- File processing
- Regular expressions
- JSON processing
- Command-line argument parsing
- Exception handling
- Type hints
- Python package structure

### 📊 Log & Data Analysis

Log events are transformed into measurable engineering metrics, including:

- Request counts
- Error rates
- 4xx / 5xx rates
- Average latency
- P50 latency
- P95 latency
- P99 latency
- Endpoint-level statistics
- Request distributions
- Time-based traffic analysis

### 🔍 Log Parsing & Normalization

Real-world logs can follow different formats and structures.

LogLens parses supported log formats and converts them into a normalized internal representation before analysis.

```text
Raw Log
   ↓
Parsing
   ↓
Normalization
   ↓
Analysis
   ↓
Insights
   ↓
Report
````

This architecture separates data ingestion from analysis and reporting, making the system easier to maintain and extend.

### 🚨 Anomaly Detection

LogLens uses measurable baselines to identify unusual application behavior.

For example, an endpoint with an unusually high error rate can be highlighted for further investigation.

The system provides diagnostic signals and investigation hints rather than claiming a definitive root cause.

### ⚡ Performance Analysis

Average latency alone does not fully describe application performance.

LogLens analyzes:

```text
P50
P95
P99
```

to provide a clearer view of response-time distribution and identify slow endpoints or requests.

### 🧪 Automated Testing

The project includes automated tests covering core functionality such as:

* Parsing
* Filtering
* Analysis
* Reporting
* Statistics
* Edge cases

**Current test suite:**

```text
41 tests
41 passed
```

### 🔄 Regression Analysis

LogLens can compare two log datasets to identify changes in application behavior.

The comparison includes metrics such as:

* Error rate
* 5xx rate
* Average latency
* P95 latency
* Health score
* Endpoint-level failures

```text
Previous Logs
      ↓
    Compare
      ↑
Current Logs
      ↓
Regression Insights
```

This provides a practical approach to investigating whether application behavior changed after a deployment or code modification.

---

## 🧠 Key Learning Outcomes

The project demonstrates practical experience with:

* Log processing and observability concepts
* Statistical analysis of application behavior
* Performance monitoring
* Anomaly detection using rule-based analysis
* Regression analysis
* CLI application development
* Modular software architecture
* Automated testing
* Structured reporting
* Error handling and defensive programming
* Git and GitHub workflows
* Technical documentation

---

## 💡 Engineering Takeaway

The core principle behind LogLens is:

> **Raw logs become valuable when they are transformed into measurable information that supports investigation and engineering decisions.**

The complete processing pipeline can be represented as:

```text
Raw Application Logs
        ↓
     Parsing
        ↓
   Normalization
        ↓
 Statistical Analysis
        ↓
Error & Performance Insights
        ↓
 Anomaly Detection
        ↓
   Health Scoring
        ↓
   Regression Analysis
        ↓
 Actionable Reports
```

---

## 👩‍💻 Author

### Ashvitha Reddy

Computer Science Engineering Student

**Areas of Interest**

* Software Engineering
* Artificial Intelligence & Machine Learning
* Cybersecurity
* Cloud Computing
* Developer Tools

GitHub: [@pashvithareddy-debug](https://github.com/pashvithareddy-debug)

---

<div align="center">

### 🔍 LogLens

**Turn raw application logs into actionable engineering insights.**

Built by **Ashvitha Reddy** as a practical developer-tool project.

</div>

