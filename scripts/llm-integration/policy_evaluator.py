#!/usr/bin/env python3  
import argparse  
import json  
import os  
import re  
from typing import Dict, List, Optional  
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction  
from rouge_score import rouge_scorer  
  
def parse_arguments():  
    """Parse command-line arguments"""  
    parser = argparse.ArgumentParser(  
        description='Evaluate generated policies against NIST/ISO reference templates using BLEU and ROUGE-L'  
    )  
    parser.add_argument('--deepseek-policies', required=True,   
                       help='Path to DeepSeek generated policies markdown file')  
    parser.add_argument('--llama-policies', required=True,   
                       help='Path to LLaMA generated policies markdown file')  
    parser.add_argument('--reference-policies', required=True,   
                       help='Path to reference policies JSON file (NIST/ISO templates)')  
    parser.add_argument('--output-dir', required=True,   
                       help='Output directory for evaluation results')  
    return parser.parse_args()  
  
def load_policy_file(file_path: str) -> str:  
    """Load policy markdown file"""  
    if not os.path.exists(file_path):  
        print(f"⚠️  Warning: {file_path} not found")  
        return ""  
    with open(file_path, 'r', encoding='utf-8') as f:  
        return f.read()  
  
def load_reference_policies(file_path: str) -> Dict:  
    """Load reference policies from JSON"""  
    if not os.path.exists(file_path):  
        print(f"❌ ERROR: Reference policies file not found: {file_path}")  
        return {}  
      
    with open(file_path, 'r', encoding='utf-8') as f:  
        return json.load(f)  
  
def extract_policies(content: str) -> List[Dict[str, str]]:  
    """Extract policies with their components from markdown"""  
    policies = []  
    policy_blocks = [p.strip() for p in content.split('---') if p.strip()]  
      
    for block in policy_blocks:  
        policy = {}  
          
        # Extract title  
        title_match = re.search(r'\*\*Policy Title:\*\*\s*(.+)', block)  
        if title_match:  
            policy['title'] = title_match.group(1).strip()  
          
        # Extract policy statement  
        statement_match = re.search(  
            r'\*\*Policy Statement:\*\*\s*(.+?)(?=\*\*|$)',   
            block, re.DOTALL  
        )  
        if statement_match:  
            policy['statement'] = statement_match.group(1).strip()  
          
        # Extract implementation requirements  
        impl_match = re.search(  
            r'\*\*Implementation Requirements:\*\*\s*(.+?)(?=\*\*|$)',   
            block, re.DOTALL  
        )  
        if impl_match:  
            policy['implementation'] = impl_match.group(1).strip()  
          
        # Extract verification method  
        verif_match = re.search(  
            r'\*\*Verification Method:\*\*\s*(.+?)(?=\*\*|$)',   
            block, re.DOTALL  
        )  
        if verif_match:  
            policy['verification'] = verif_match.group(1).strip()  
          
        # Extract NIST CSF reference  
        nist_match = re.search(r'\*\*NIST CSF Reference:\*\*\s*(.+)', block)  
        if nist_match:  
            policy['nist_csf'] = nist_match.group(1).strip()  
          
        # Extract ISO 27001 reference  
        iso_match = re.search(r'\*\*ISO 27001 Reference:\*\*\s*(.+)', block)  
        if iso_match:  
            policy['iso_27001'] = iso_match.group(1).strip()  
          
        if policy:  # Only add if we extracted something  
            policies.append(policy)  
      
    return policies  
  
def map_policy_to_reference(policy_title: str, references: Dict) -> Optional[str]:  
    """Map a generated policy to its reference template based on keywords"""  
    title_lower = policy_title.lower()  
      
    # Mapping logic based on keywords in policy titles  
    if 'hardcoded' in title_lower or 'secret' in title_lower:  
        return 'hardcoded_secrets'  
    elif 'object injection' in title_lower or 'injection' in title_lower:  
        return 'object_injection'  
    elif 'eval' in title_lower or 'arbitrary code' in title_lower or 'code execution' in title_lower:  
        return 'arbitrary_code_execution'  
    elif 'dependency' in title_lower or 'dependencies' in title_lower or 'sca' in title_lower:  
        return 'vulnerable_dependencies'  
    elif 'csp' in title_lower and 'directive' in title_lower:  
        return 'csp_directive_missing'  
    elif 'csp' in title_lower or 'content security policy' in title_lower:  
        return 'csp_header_not_set'  
    elif 'cors' in title_lower or 'cross-domain' in title_lower or 'cross-origin' in title_lower:  
        return 'cors_misconfiguration'  
    elif 'clickjacking' in title_lower or 'x-frame-options' in title_lower or 'frame' in title_lower:  
        return 'clickjacking'  
    elif 'permissions policy' in title_lower or 'feature-policy' in title_lower:  
        return 'permissions_policy'  
      
    return None  
  
def calculate_bleu(reference: str, candidate: str) -> float:  
    """Calculate BLEU score between reference and candidate text"""  
    smoothing = SmoothingFunction().method1  
    reference_tokens = reference.split()  
    candidate_tokens = candidate.split()  
      
    if not reference_tokens or not candidate_tokens:  
        return 0.0  
      
    return sentence_bleu([reference_tokens], candidate_tokens, smoothing_function=smoothing)  
  
def calculate_rouge(reference: str, candidate: str) -> Dict[str, float]:  
    """Calculate ROUGE-L scores"""  
    scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)  
      
    if not reference or not candidate:  
        return {'precision': 0.0, 'recall': 0.0, 'fmeasure': 0.0}  
      
    scores = scorer.score(reference, candidate)  
    return {  
        'precision': scores['rougeL'].precision,  
        'recall': scores['rougeL'].recall,  
        'fmeasure': scores['rougeL'].fmeasure  
    }  
  
def evaluate_policy_against_reference(  
    generated_policy: Dict,   
    reference_policy: Dict  
) -> Dict:  
    """Evaluate a single policy against its reference template"""  
    results = {}  
      
    # Evaluate each component (statement, implementation, verification)  
    for component in ['statement', 'implementation', 'verification']:  
        if component in generated_policy and component in reference_policy:  
            gen_text = generated_policy.get(component, '')  
            ref_text = reference_policy.get(f'policy_{component}' if component == 'statement' else component, '')  
              
            # Calculate BLEU score  
            results[f'{component}_bleu'] = calculate_bleu(ref_text, gen_text)  
              
            # Calculate ROUGE-L score  
            rouge_scores = calculate_rouge(ref_text, gen_text)  
            results[f'{component}_rouge_l_precision'] = rouge_scores['precision']  
            results[f'{component}_rouge_l_recall'] = rouge_scores['recall']  
            results[f'{component}_rouge_l_fmeasure'] = rouge_scores['fmeasure']  
      
    # Check NIST CSF compliance  
    results['nist_csf_match'] = (  
        generated_policy.get('nist_csf', '').strip() ==   
        reference_policy.get('nist_csf', '').strip()  
    )  
      
    # Check ISO 27001 compliance  
    results['iso_27001_match'] = (  
        generated_policy.get('iso_27001', '').strip() ==   
        reference_policy.get('iso_27001', '').strip()  
    )  
      
    # Calculate overall score (average of all BLEU and ROUGE-L F-measures)  
    metric_values = []  
    for key, value in results.items():  
        if isinstance(value, float) and 'bleu' in key or 'fmeasure' in key:  
            metric_values.append(value)  
      
    results['overall_score'] = sum(metric_values) / len(metric_values) if metric_values else 0.0  
      
    return results  
  
def calculate_averages(results: List[Dict]) -> Dict:  
    """Calculate aggregate statistics from evaluation results"""  
    if not results:  
        return {}  
      
    # Calculate averages for each metric  
    avg_statement_bleu = sum(r.get('statement_bleu', 0) for r in results) / len(results)  
    avg_statement_rouge = sum(r.get('statement_rouge_l_fmeasure', 0) for r in results) / len(results)  
    avg_impl_bleu = sum(r.get('implementation_bleu', 0) for r in results) / len(results)  
    avg_impl_rouge = sum(r.get('implementation_rouge_l_fmeasure', 0) for r in results) / len(results)  
    avg_verif_bleu = sum(r.get('verification_bleu', 0) for r in results) / len(results)  
    avg_verif_rouge = sum(r.get('verification_rouge_l_fmeasure', 0) for r in results) / len(results)  
    avg_overall = sum(r.get('overall_score', 0) for r in results) / len(results)  
      
    # Calculate compliance rates  
    nist_compliance = sum(1 for r in results if r.get('nist_csf_match', False)) / len(results) * 100  
    iso_compliance = sum(1 for r in results if r.get('iso_27001_match', False)) / len(results) * 100  
      
    return {  
        'avg_statement_bleu': avg_statement_bleu,  
        'avg_statement_rouge_l': avg_statement_rouge,  
        'avg_implementation_bleu': avg_impl_bleu,  
        'avg_implementation_rouge_l': avg_impl_rouge,  
        'avg_verification_bleu': avg_verif_bleu,  
        'avg_verification_rouge_l': avg_verif_rouge,  
        'avg_overall_score': avg_overall,  
        'nist_csf_compliance_rate': nist_compliance,  
        'iso_27001_compliance_rate': iso_compliance  
    }  
  
def main():  
    """Main evaluation function"""  
    print("="*70)  
    print("🔍 POLICY EVALUATION: BLEU & ROUGE-L Analysis")  
    print("="*70)  
      
    args = parse_arguments()  
      
    # Load files  
    print("\n📂 Loading files...")  
    deepseek_content = load_policy_file(args.deepseek_policies)  
    llama_content = load_policy_file(args.llama_policies)  
    reference_policies = load_reference_policies(args.reference_policies)  
      
    if not reference_policies:  
        print("❌ Cannot proceed without reference policies")  
        return  
      
    # Extract policies  
    print("📋 Extracting policies...")  
    deepseek_policies = extract_policies(deepseek_content)  
    llama_policies = extract_policies(llama_content)  
      
    print(f"✓ Found {len(deepseek_policies)} DeepSeek policies")  
    print(f"✓ Found {len(llama_policies)} LLaMA policies")  
    print(f"✓ Loaded {len(reference_policies)} reference templates\n")  
      
    # Evaluate DeepSeek policies  
    print("🤖 Evaluating DeepSeek policies against NIST/ISO references...")  
    deepseek_results = []  
    for policy in deepseek_policies:  
        ref_key = map_policy_to_reference(policy.get('title', ''), reference_policies)  
        if ref_key and ref_key in reference_policies:  
            evaluation = evaluate_policy_against_reference(policy, reference_policies[ref_key])  
            evaluation['policy_title'] = policy.get('title', 'Unknown')  
            evaluation['reference_type'] = ref_key  
            deepseek_results.append(evaluation)  
            print(f"  ✓ Evaluated: {policy.get('title', 'Unknown')[:50]}...")  
      
    # Evaluate LLaMA policies  
    print("\n🦙 Evaluating LLaMA policies against NIST/ISO references...")  
    llama_results = []  
    for policy in llama_policies:  
        ref_key = map_policy_to_reference(policy.get('title', ''), reference_policies)  
        if ref_key and ref_key in reference_policies:  
            evaluation = evaluate_policy_against_reference(policy, reference_policies[ref_key])  
            evaluation['policy_title'] = policy.get('title', 'Unknown')  
            evaluation['reference_type'] = ref_key  
            llama_results.append(evaluation)  
            print(f"  ✓ Evaluated: {policy.get('title', 'Unknown')[:50]}...")  
      
    # Calculate aggregate statistics  
    deepseek_summary = calculate_averages(deepseek_results)  
    llama_summary = calculate_averages(llama_results)  
      
    # Prepare final report  
    final_report = {  
        'evaluation_metadata': {  
            'evaluation_type': 'Generated Policies vs NIST/ISO Reference Templates',  
            'metrics_used': ['BLEU', 'ROUGE-L'],  
            'reference_file': args.reference_policies  
        },  
        'deepseek': {  
            'num_policies_evaluated': len(deepseek_results),  
            'summary': deepseek_summary,  
            'detailed_results': deepseek_results  
        },  
        'llama': {  
            'num_policies_evaluated': len(llama_results),  
            'summary': llama_summary,  
            'detailed_results': llama_results  
        },  
        'comparative_analysis': {  
            'winner_overall': 'DeepSeek' if deepseek_summary.get('avg_overall_score', 0) > llama_summary.get('avg_overall_score', 0) else 'LLaMA',  
            'score_difference': abs(deepseek_summary.get('avg_overall_score', 0) - llama_summary.get('avg_overall_score', 0)),  
            'deepseek_advantages': [],  
            'llama_advantages': []  
        }  
    }  
      
    # Identify advantages  
    if deepseek_summary.get('avg_statement_bleu', 0) > llama_summary.get('avg_statement_bleu', 0):  
        final_report['comparative_analysis']['deepseek_advantages'].append('Better policy statement quality (BLEU)')  
    else:  
        final_report['comparative_analysis']['llama_advantages'].append('Better policy statement quality (BLEU)')  
      
    if deepseek_summary.get('nist_csf_compliance_rate', 0) > llama_summary.get('nist_csf_compliance_rate', 0):  
        final_report['comparative_analysis']['deepseek_advantages'].append('Higher NIST CSF compliance rate')  
    else:  
        final_report['comparative_analysis']['llama_advantages'].append('Higher NIST CSF compliance rate')  
      
    if deepseek_summary.get('iso_27001_compliance_rate', 0) > llama_summary.get('iso_27001_compliance_rate', 0):  
        final_report['comparative_analysis']['deepseek_advantages'].append('Higher ISO 27001 compliance rate')  
    else:  
        final_report['comparative_analysis']['llama_advantages'].append('Higher ISO 27001 compliance rate')  
      
    # Save results  
    os.makedirs(args.output_dir, exist_ok=True)  
    output_file = os.path.join(args.output_dir, 'evaluation_report.json')  
      
    with open(output_file, 'w', encoding='utf-8') as f:  
        json.dump(final_report, f, indent=2)  
      
    # Print summary  
    print("\n" + "="*70)  
    print("📊 EVALUATION SUMMARY")  
    print("="*70)  
    print(f"\n🤖 DeepSeek Results:")  
    print(f"  Overall Score: {deepseek_summary.get('avg_overall_score', 0):.4f}")  
    print(f"  Statement BLEU: {deepseek_summary.get('avg_statement_bleu', 0):.4f}")  
    print(f"  Implementation BLEU: {deepseek_summary.get('avg_implementation_bleu', 0):.4f}")  
    print(f"  Verification BLEU: {deepseek_summary.get('avg_verification_bleu', 0):.4f}")  
    print(f"  NIST CSF Compliance: {deepseek_summary.get('nist_csf_compliance_rate', 0):.1f}%")  
    print(f"  ISO 27001 Compliance: {deepseek_summary.get('iso_27001_compliance_rate', 0):.1f}%")  
      
    print(f"\n🦙 LLaMA Results:")  
    print(f"  Overall Score: {llama_summary.get('avg_overall_score', 0):.4f}")  
    print(f"  Statement BLEU: {llama_summary.get('avg_statement_bleu', 0):.4f}")  
    print(f"  Implementation BLEU: {llama_summary.get('avg_implementation_bleu', 0):.4f}")  
    print(f"  Verification BLEU: {llama_summary.get('avg_verification_bleu', 0):.4f}")  
    print(f"  NIST CSF Compliance: {llama_summary.get('nist_csf_compliance_rate', 0):.1f}%")  
    print(f"  ISO 27001 Compliance: {llama_summary.get('iso_27001_compliance_rate', 0):.1f}%")  
      
    print(f"\n🏆 Winner: {final_report['comparative_analysis']['winner_overall']}")  
    print(f"  Score Difference: {final_report['comparative_analysis']['score_difference']:.4f}")  
      
    if final_report['comparative_analysis']['deepseek_advantages']:  
        print(f"\n✅ DeepSeek Advantages:")  
        for adv in final_report['comparative_analysis']['deepseek_advantages']:  
            print(f"  • {adv}")  
      
    if final_report['comparative_analysis']['llama_advantages']:  
        print(f"\n✅ LLaMA Advantages:")  
        for adv in final_report['comparative_analysis']['llama_advantages']:  
            print(f"  • {adv}")  
      
    print("\n" + "="*70)  
    print(f"✅ Evaluation report saved to: {output_file}")  
    print("="*70)  
  
if __name__ == '__main__':  
    main()