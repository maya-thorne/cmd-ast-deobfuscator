---
library_name: transformers
language:
- ko
metrics:
- f1
base_model:
- google/gemma-2-2b-it
---

# Dacon 난독화 데이터셋 파인튜닝 

- 원본 대회 정보
- `Dacon`
![image/png](https://cdn-uploads.huggingface.co/production/uploads/660268ab561089b1a7016e4f/jRE_JK77cK2yD-mvVJlBs.png)

대회 링크 
[https://dacon.io](https://dacon.io/competitions/official/236446/overview/description)

- `Machine Spec`
- `GCP V100`
  - 실행 `Spec`
    - `batch_size : 10, max_length : 128, trl, peft, BitsAndBytesConfig, bfloat16으로 실행`
    - `total loss : 3.8`

  - 위 모델의 데이터는 `Dacon`을 통해 제공 받았으며, 해당 모델은 비영리적으로 사용할 예정 입니다(포트폴리오용, 시험 제출용)
  - `google/gemma-2-2b-it` fine-tune
