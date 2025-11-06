#!/usr/bin/env python3  
import argparse  
import json  
import os  
from typing import Dict, List  
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction  
from rouge_score import rouge_scorer  
  
def parse_arguments():  
    parser = argparse.ArgumentParser(description='Evaluate generated policies with BLEU and ROUGE-L')  
    parser.add_argument('--deepseek-policies', required=True, help='Path to DeepSeek policies file')  
    parser.add_argument('--llama-policies', required=True, help='Path to LLaMA policies file')  
    parser.add_argument('--output-dir', required=True, help='Output directory for evaluation results')  
    return parser.parse_args()  
  
def load_policy_file(file_path: str) -> str:  
    """Load policy markdown file"""  
    if not os.path.exists(file_path):  
        print(f"Warning: {file_path} not found")  
        return ""  
    with open(file_path, 'r', encoding='utf-8') as f:  
        return f.read()  
  
def extract_policies(content: str) -> List[str]:  
    """Split policies by separator"""  
    return [p.strip() for p in content.split('---') if p.strip()]  
  
def calculate_bleu(reference: str, candidate: str) -> float:  
    """Calculate BLEU score between two texts"""  
    smoothing = SmoothingFunction().method1  
    reference_tokens = reference.split()  
    candidate_tokens = candidate.split()  
    return sentence_bleu([reference_tokens], candidate_tokens, smoothing_function=smoothing)  
  
def calculate_rouge(reference: str, candidate: str) -> Dict[str, float]:  
    """Calculate ROUGE-L score"""  
    scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)  
    scores = scorer.score(reference, candidate)  
    return {  
        'precision': scores['rougeL'].precision,  
        'recall': scores['rougeL'].recall,  
        'fmeasure': scores['rougeL'].fmeasure  
    }  
  
def main():  
    args = parse_arguments()  
      
    # Load policies  
    deepseek_content = load_policy_file(args.deepseek_policies)  
    llama_content = load_policy_file(args.llama_policies)  
      
    deepseek_policies = extract_policies(deepseek_content)  
    llama_policies = extract_policies(llama_content)  
      
    # Calculate metrics (comparing DeepSeek vs LLaMA)  
    results = {  
        'comparison_type': 'DeepSeek vs LLaMA',  
        'num_deepseek_policies': len(deepseek_policies),  
        'num_llama_policies': len(llama_policies),  
        'policy_comparisons': []  
    }  
      
    # Compare policies pairwise  
    for i in range(min(len(deepseek_policies), len(llama_policies))):  
        bleu = calculate_bleu(deepseek_policies[i], llama_policies[i])  
        rouge = calculate_rouge(deepseek_policies[i], llama_policies[i])  
          
        results['policy_comparisons'].append({  
            'policy_index': i + 1,  
            'bleu_score': bleu,  
            'rouge_l_precision': rouge['precision'],  
            'rouge_l_recall': rouge['recall'],  
            'rouge_l_fmeasure': rouge['fmeasure']  
        })  
      
    # Calculate averages  
    if results['policy_comparisons']:  
        avg_bleu = sum(p['bleu_score'] for p in results['policy_comparisons']) / len(results['policy_comparisons'])  
        avg_rouge_f = sum(p['rouge_l_fmeasure'] for p in results['policy_comparisons']) / len(results['policy_comparisons'])  
          
        results['summary'] = {  
            'average_bleu': avg_bleu,  
            'average_rouge_l_fmeasure': avg_rouge_f  
        }  
      
    # Save results  
    os.makedirs(args.output_dir, exist_ok=True)  
    output_file = os.path.join(args.output_dir, 'evaluation_report.json')  
      
    with open(output_file, 'w', encoding='utf-8') as f:  
        json.dump(results, f, indent=2)  
      
    print(f"✓ Evaluation complete. Results saved to: {output_file}")  
    if 'summary' in results:  
        print(f"  Average BLEU: {results['summary']['average_bleu']:.4f}")  
        print(f"  Average ROUGE-L F-measure: {results['summary']['average_rouge_l_fmeasure']:.4f}")  
  
if __name__ == '__main__':  
    main()