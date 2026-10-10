---
dataset_info:
  features:
  - name: sentence_noisy
    dtype: string
  - name: sentence
    dtype: string
  splits:
  - name: train
    num_bytes: 4041412
    num_examples: 9008
  - name: dev
    num_bytes: 529536
    num_examples: 1126
  - name: test
    num_bytes: 535044
    num_examples: 1126
  download_size: 3795502
  dataset_size: 5105992
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*
  - split: dev
    path: data/dev-*
  - split: test
    path: data/test-*
---
