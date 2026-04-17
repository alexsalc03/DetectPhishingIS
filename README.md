# DetectPhishingIS
# Metadata-Centric Phishing Detection with Host-Level Infrastructure Profiling

A research project on phishing detection based on **host-level infrastructure metadata** rather than page content.  
The pipeline starts from phishing and benign domain sources, normalizes them to a host representation, enriches them with **Censys** metadata, engineers security-relevant features, and trains interpretable machine learning models to distinguish **phishing-related** from **benign** hosts.

The final goal is not only to obtain a strong classifier, but also to understand **which infrastructure signals matter most** in phishing detection.

---

## Project Overview

Traditional phishing detection often relies on page content, HTML structure, visual similarity, or URL lexical patterns. These approaches can be effective, but they may become less reliable when phishing pages are short-lived, rapidly rotated, or hidden behind changing infrastructure.

This project explores a different perspective:

- start from **domain-level ground truth**
- resolve domains to **IPv4 hosts**
- collect **host metadata** from Censys
- build a structured tabular dataset
- train interpretable classifiers
- analyze which host-level signals are associated with phishing

The central idea is that phishing infrastructure may reveal detectable patterns through metadata such as:

- exposed services and port configuration
- HTTP behavior
- TLS certificate properties
- DNS naming structure
- WHOIS and network age indicators

---

## Objectives

This project has two main objectives:

1. **Detection objective**  
   Evaluate whether infrastructure-level metadata can help distinguish phishing-related hosts from benign hosts.

2. **Interpretability objective**  
   Identify which features carry the strongest discriminative signal, and understand how iterative dataset refinement improves both predictive performance and analytical quality.

---

## Research Questions

The project is guided by the following questions:

- Can phishing-related hosts be distinguished from benign hosts using host-level metadata alone?
- Which infrastructure signals are most informative?
- Does iterative feature refinement improve both model performance and stability?
- Can a simple and interpretable model provide meaningful insight into phishing infrastructure?

---

## Dataset Sources

The pipeline combines two categories of input domains:

### Phishing domains
Phishing samples are collected from **OpenPhish**, which provides known phishing URLs/domains.

### Benign domains
Benign samples are collected from **Tranco**, used as a source of legitimate and popular domains.

These inputs are later normalized and mapped to host-level observations.

---

## Methodology

The full pipeline is organized into several stages.

### 1. Data preparation and normalization
- Clean source files
- Remove formatting artifacts
- Deduplicate domains
- Normalize entries to a consistent domain format

For benign domains, rank prefixes from Tranco-style lists are removed so that only the domain name remains.

### 2. Domain-to-host resolution
Each domain is resolved to a **single IPv4 address**.

This produces one host-level representation per domain and aligns the dataset with the host-centric structure used by Censys.

Domains that cannot be resolved are excluded from downstream processing.

### 3. Metadata acquisition through Censys
For each resolved IPv4 address, a **Censys host lookup** is performed through the API.

Collected metadata may include:

- host identity
- geolocation
- autonomous system information
- WHOIS-related fields
- open ports and service exposure
- HTTP endpoint metadata
- TLS certificate information
- DNS-related names
- timestamps and observation metadata

Raw responses are stored for traceability, and collection outcomes are logged.

### 4. Feature engineering
Raw metadata is transformed into structured features suitable for machine learning.

Feature families include:

- **Network and WHOIS features**
  - network age
  - autonomous system context
- **Port and service exposure**
  - number of exposed ports
  - presence of non-web ports
  - port-count buckets
- **HTTP behavior**
  - root path response type
  - redirect-like behavior
  - HTML content indicators
  - HTTP/2 support
- **Server characteristics**
  - server-family grouping
- **TLS and certificate features**
  - certificate presence
  - certificate validation group
  - remaining validity
  - chain length
  - short-lived or recently issued certificates
- **DNS-based lexical/structural signals**
  - number of labels
  - label length
  - entropy
  - suspicious token patterns
  - digit/hyphen patterns
  - punycode
  - brand/auth combinations

### 5. Dataset refinement
The dataset evolves through multiple versions (**v2**, **v3**, **v4**), with each version refining feature construction and improving analytical consistency.

The final version, **v4**, represents the endpoint of the iterative refinement process.

### 6. Modeling
The project uses **interpretable machine learning models**, primarily:

- **Logistic Regression**

The emphasis is on:
- transparent coefficients
- stable feature interpretation
- meaningful comparison across dataset versions

### 7. Evaluation
Models are evaluated using metrics such as:

- ROC-AUC
- Average Precision
- Accuracy
- Precision
- Recall
- False Alarm Rate

In addition to predictive performance, the project also evaluates:
- coefficient stability
- feature consistency
- interpretability of the learned signals

---

## Final Result

The final **v4** dataset showed that infrastructure-level metadata can effectively support the distinction between phishing-related and benign hosts.

Compared with earlier versions, the final representation improved not only predictive performance but also the clarity and stability of the feature space. The resulting model highlighted several meaningful phishing-associated indicators, including:

- broader exposure of services
- presence of non-web ports
- successful HTML responses at the root path
- weaker certificate validation profiles
- server-family patterns consistent with lightweight or self-managed infrastructure

At the same time, benign hosts were more associated with signals such as:

- older and more established network context
- stronger certificate validation
- more regular HTTP/2 support
- more structured and mature infrastructure traits

---


## Pipeline Summary

The end-to-end workflow is:
1. Collect phishing and benign domain sources
2. Clean and normalize domains
3. Resolve domains to IPv4 addresses
4. Query Censys for host metadata
5. Save raw responses and logs
6. Engineer structured features
7. Build versioned datasets
8. Train interpretable models
9. Evaluate performance
10. Analyze feature importance and stability

## Key Features

Some of the most important engineered features in the final version include:
- `whois_network_age_days`
- `port_count_bucket`
- `has_non_web_ports`
- `root_2xx_html`
- `root_redirect_like`
- `http_any_is_html`
- `http_any_supports_http2`
- `server_family`
- `cert_present`
- `cert_validation_group`
- `cert_remaining_days`
- `cert_chain_len`
- `cert_recently_issued`
- `cert_short_lived`
- `cert_age_ratio`
- `has_dns_names_data`
- `dns_num_labels`
- `dns_max_label_length`
- `dns_label_entropy`
- `dns_brand_plus_auth_combo`
- `dns_has_brand_token`
- `dns_suspicious_token_count`
- `dns_has_digit_hyphen_pattern`
- `dns_has_punycode`


Citation

If you use this project in academic or research work, please cite the corresponding thesis, report, or repository. Example:

@misc{metadata_phishing_detection,
  author = {Francesco Alexander Salcuni},
  title = {Unmask the Phish: ML-driven
Metadata Profiling of Malicious
Hosts},
  year = {2026},
  note = {Independent Study / Research Project},
  howpublished = {GitHub repository}
}

Author

Francesco Alexander Salcuni
