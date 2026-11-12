Phishing Detection Tool – Documentation

1. Project Overview

This document presents the development and testing of the Phishing Detection Tool.

The tool is developed using Python to analyze URLs and identify suspicious indicators that may be associated with phishing attempts.

The analysis is based on predefined rules. Each detected indicator contributes to a risk score and is recorded in the analysis findings.

2. Source Code Analysis

Figure 02-A – Basic URL Analysis

The following code performs the initial URL checks.

- Initializes the risk score and findings list.
- Validates the URL format and extracts the domain.
- Checks HTTPS usage.
- Detects URLs that use an IP address.
- Searches for suspicious keywords.

Each detected indicator adds points to the risk score and is recorded in the findings list.
