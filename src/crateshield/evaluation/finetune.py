import os
import torch
import logging
from pathlib import Path
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

from crateshield.config import ROOT

logger = logging.getLogger(__name__)

DISTILL_DIR = ROOT / "data" / "distillation"
OUTPUT_DIR = ROOT / "models" / "finetuned"
MODEL_ID = "Qwen/Qwen2.5-Coder-1.5B"

def format_instruction(example):
    """Formats the instruction for the SFTTrainer"""
    return f"Instruction: {example['instruction']}\nInput: {example['input']}\nOutput: {example['output']}"

def run_finetuning():
    train_file = DISTILL_DIR / "train.jsonl"
    val_file = DISTILL_DIR / "val.jsonl"
    
    if not train_file.exists() or not val_file.exists():
        logger.error(f"Cannot find train/val files in {DISTILL_DIR}")
        return

    logger.info("Loading dataset...")
    dataset = load_dataset("json", data_files={"train": str(train_file), "test": str(val_file)})

    logger.info(f"Loading tokenizer {MODEL_ID}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    tokenizer.pad_token = tokenizer.eos_token

    logger.info(f"Loading model {MODEL_ID}...")
    # Load model in 8bit or 4bit if possible, for local fine-tuning on consumer hardware. 
    # Here we assume a basic fp16 setup for simplicity, as bitsandbytes can be tricky on Windows.
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID, 
        torch_dtype=torch.float16,
        device_map="auto"
    )

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )
    
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        logging_steps=10,
        max_steps=200, # Short run for demonstration, adjust for actual training
        eval_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=50,
        fp16=True,
        optim="paged_adamw_8bit"
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset["train"],
        eval_dataset=dataset["test"],
        peft_config=lora_config,
        formatting_func=lambda x: [format_instruction(item) for item in zip(x["instruction"], x["input"], x["output"])],
        args=training_args,
        tokenizer=tokenizer,
    )

    logger.info("Starting training...")
    trainer.train()

    logger.info(f"Saving model to {OUTPUT_DIR}/final")
    trainer.save_model(str(OUTPUT_DIR / "final"))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_finetuning()
