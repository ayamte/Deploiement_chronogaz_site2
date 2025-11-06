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
    parser.add_argument('--reference-policies', required=False, help='Path to reference policies JSON')  
    parser.add_argument('--output-dir', required=True, help='Output directory for evaluation results')  
    return parser.parse_args()  
  
def load_policy_file(file_path: str) -> str:  
    """Load policy markdown file"""  
    if not os.path.exists(file_path):  
        print(f"Warning: {file_path} not found")  
        return ""  
    with open(file_path, 'r', encoding='utf-8') as f:  
        return f.read()  
  
def load_reference_policies(file_path: str) -> Dict:  
    """Load reference policies JSON"""  
    if not file_path or not os.path.exists(file_path):  
        return None  
    with open(file_path, 'r', encoding='utf-8') as f:  
        return json.load(f)  
  
def extract_policies(content: str) -> List[str]:  
    """Split policies by separator"""  
    return [p.strip() for p in content.split('---') if p.strip()]  
  
def extract_policy_title(policy_text: str) -> str:  
    """Extract policy title from markdown"""  
    for line in policy_text.splitlines():  
        if line.startswith("**Policy Title:**"):  
            return line.replace("**Policy Title:**", "").strip()  
    return "Untitled Policy"  
  
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
  
def evaluate_against_references(deepseek_policies: List[str], llama_policies: List[str],   
                                reference_data: Dict) -> Dict:  
    """Evaluate both models against reference policies"""  
    results = {  
        'evaluation_type': 'Against Reference Policies',  
        'deepseek_scores': [],  
        'llama_scores': [],  
        'deepseek_summary': {},  
        'llama_summary': {}  
    }  
      
    # Build a mapping of policy titles to generated policies  
    deepseek_map = {extract_policy_title(p): p for p in deepseek_policies}  
    llama_map = {extract_policy_title(p): p for p in llama_policies}  
      
    deepseek_bleu_scores = []  
    deepseek_rouge_scores = []  
    llama_bleu_scores = []  
    llama_rouge_scores = []  
      
    for ref_vuln in reference_data.get('vulnerabilities', []):  
        ref_name = ref_vuln['name']  
        ref_policy = ref_vuln['reference_policy']  
          
        # Find matching generated policies (fuzzy match by name)  
        deepseek_policy = None  
        llama_policy = None  
          
        for title, policy in deepseek_map.items():  
            if ref_name.lower() in title.lower() or title.lower() in ref_name.lower():  
                deepseek_policy = policy  
                break  
          
        for title, policy in llama_map.items():  
            if ref_name.lower() in title.lower() or title.lower() in ref_name.lower():  
                llama_policy = policy  
                break  
          
        # Evaluate DeepSeek  
        if deepseek_policy:  
            bleu = calculate_bleu(ref_policy, deepseek_policy)  
            rouge = calculate_rouge(ref_policy, deepseek_policy)  
            deepseek_bleu_scores.append(bleu)  
            deepseek_rouge_scores.append(rouge['fmeasure'])  
            results['deepseek_scores'].append({  
                'vulnerability': ref_name,  
                'bleu': bleu,  
                'rouge_l_fmeasure': rouge['fmeasure']  
            })  
          
        # Evaluate LLaMA  
        if llama_policy:  
            bleu = calculate_bleu(ref_policy, llama_policy)  
            rouge = calculate_rouge(ref_policy, llama_policy)  
            llama_bleu_scores.append(bleu)  
            llama_rouge_scores.append(rouge['fmeasure'])  
            results['llama_scores'].append({  
                'vulnerability': ref_name,  
                'bleu': bleu,  
                'rouge_l_fmeasure': rouge['fmeasure']  
            })  
      
    # Calculate averages  
    if deepseek_bleu_scores:  
        results['deepseek_summary'] = {  
            'average_bleu': sum(deepseek_bleu_scores) / len(deepseek_bleu_scores),  
            'average_rouge_l': sum(deepseek_rouge_scores) / len(deepseek_rouge_scores)  
        }  
      
    if llama_bleu_scores:  
        results['llama_summary'] = {  
            'average_bleu': sum(llama_bleu_scores) / len(llama_bleu_scores),  
            'average_rouge_l': sum(llama_rouge_scores) / len(llama_rouge_scores)  
        }  
      
    return results  
  
def main():  
    args = parse_arguments()  
      
    # Load policies  
    deepseek_content = load_policy_file(args.deepseek_policies)  
    llama_content = load_policy_file(args.llama_policies)  
      
    deepseek_policies = extract_policies(deepseek_content)  
    llama_policies = extract_policies(llama_content)  
      
    # 1. Compare DeepSeek vs LLaMA (existing logic)  
    llm_comparison = {  
        'comparison_type': 'DeepSeek vs LLaMA',  
        'num_deepseek_policies': len(deepseek_policies),  
        'num_llama_policies': len(llama_policies),  
        'policy_comparisons': []  
    }  
      
    for i in range(min(len(deepseek_policies), len(llama_policies))):  
        bleu = calculate_bleu(deepseek_policies[i], llama_policies[i])  
        rouge = calculate_rouge(deepseek_policies[i], llama_policies[i])  
          
        llm_comparison['policy_comparisons'].append({  
            'policy_index': i + 1,  
            'bleu_score': bleu,  
            'rouge_l_precision': rouge['precision'],  
            'rouge_l_recall': rouge['recall'],  
            'rouge_l_fmeasure': rouge['fmeasure']  
        })  
      
    if llm_comparison['policy_comparisons']:  
        avg_bleu = sum(p['bleu_score'] for p in llm_comparison['policy_comparisons']) / len(llm_comparison['policy_comparisons'])  
        avg_rouge_f = sum(p['rouge_l_fmeasure'] for p in llm_comparison['policy_comparisons']) / len(llm_comparison['policy_comparisons'])  
          
        llm_comparison['summary'] = {  
            'average_bleu': avg_bleu,  
            'average_rouge_l_fmeasure': avg_rouge_f  
        }  
      
    # 2. Evaluate against reference policies (new logic)  
    reference_evaluation = None  
    reference_data = load_reference_policies(args.reference_policies)  
      
    if reference_data:  
        print("Evaluating against reference policies...")  
        reference_evaluation = evaluate_against_references(deepseek_policies, llama_policies, reference_data)  
      
    # Combine results  
    final_results = {  
        'llm_comparison': llm_comparison,  
        'reference_evaluation': reference_evaluation  
    }  
      
    # Save results  
    os.makedirs(args.output_dir, exist_ok=True)  
    output_file = os.path.join(args.output_dir, 'evaluation_report.json')  
      
    with open(output_file, 'w', encoding='utf-8') as f:  
        json.dump(final_results, f, indent=2)  
      
    print(f"✓ Evaluation complete. Results saved to: {output_file}")  
      
    # Print summary  
    if 'summary' in llm_comparison:  
        print(f"\n=== LLM Comparison (DeepSeek vs LLaMA) ===")  
        print(f"  Average BLEU: {llm_comparison['summary']['average_bleu']:.4f}")  
        print(f"  Average ROUGE-L F-measure: {llm_comparison['summary']['average_rouge_l_fmeasure']:.4f}")  
      
    if reference_evaluation:  
        print(f"\n=== Evaluation Against Reference Policies ===")  
        if reference_evaluation.get('deepseek_summary'):  
            print(f"  DeepSeek - BLEU: {reference_evaluation['deepseek_summary']['average_bleu']:.4f}, ROUGE-L: {reference_evaluation['deepseek_summary']['average_rouge_l']:.4f}")  
        if reference_evaluation.get('llama_summary'):  
            print(f"  LLaMA - BLEU: {reference_evaluation['llama_summary']['average_bleu']:.4f}, ROUGE-L: {reference_evaluation['llama_summary']['average_rouge_l']:.4f}")  
  
if __name__ == '__main__':  
    main()
