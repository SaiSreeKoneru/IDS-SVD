Dataset: https://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html

# Intrusion Detection System using SVM Variants with KDD99 Dataset

## Overview

This project implements an Intrusion Detection System (IDS) using Support Vector Machine (SVM) variants to classify network traffic into normal or intrusive activity. The IDS is trained and evaluated on the KDD99 dataset, which contains network connection records labeled as normal or attack types.

## Features

- Utilizes various SVM variants, including but not limited to:
  - Linear SVM
  - Polynomial SVM
  - Gaussian (RBF) SVM
  - Sigmoid SVM
- Implements feature engineering techniques for preprocessing the KDD99 dataset, including:
  - Data cleaning and normalization
  - Feature scaling
  - Feature selection
- Evaluates model performance using metrics such as accuracy, precision, recall, and F1-score.
- Provides visualization of evaluation metrics and classification results.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/username/intrusion-detection-svm.git

Install Dependencies:

pip install -r requirements.txt

Usage:

python svmvariants.py



