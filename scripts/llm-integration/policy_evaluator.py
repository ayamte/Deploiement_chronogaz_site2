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
        
        if policy:
            policies.append(policy)
    
    return policies

def map_policy_to_reference(policy_title: str, reference_policies: Dict) -> Optional[str]:
    """Map a generated policy to its reference template based on title keywords"""
    title_lower = policy_title.lower()
    
    # Mapping keywords to reference keys
    mappings = {
        'hardcoded': 'hardcoded_secrets',
        'secret': 'hardcoded_secrets',
        'credential': 'hardcoded_secrets',
        'object injection': 'object_injection',
        'injection': 'object_injection',
        'eval': 'arbitrary_code_execution',
        'arbitrary code': 'arbitrary_code_execution',
        'code execution': 'arbitrary_code_execution',
        'vulnerable': 'vulnerable_dependencies',
        'dependency': 'vulnerable_dependencies',
        'dependencies': 'vulnerable_dependencies',
        'sca': 'vulnerable_dependencies',
        'csp directive': 'csp_directive_missing',
        'directive': 'csp_directive_missing',
        'csp header': 'csp_header_not_set',
        'content security policy': 'csp_header_not_set',
        'cors': 'cors_misconfiguration',
        'cross-domain': 'cors_misconfiguration',
        'cross-origin': 'cors_misconfiguration',
        'clickjacking': 'clickjacking',
        'x-frame-options': 'clickjacking',
        'frame': 'clickjacking',
        'permissions policy': 'permissions_policy',
        'permissions-policy': 'permissions_policy',
        'feature-policy': 'permissions_policy'
    }
    
    for keyword, ref_key in mappings.items():
        if keyword in title_lower and ref_key in reference_policies:
            return ref_key
    
    return None

def calculate_bleu(reference: str, candidate: str) -> float:
    """Calculate BLEU score between two texts"""
    if not reference or not candidate:
        return 0.0
    
    smoothing = SmoothingFunction().method1
    reference_tokens = reference.split()
    candidate_tokens = candidate.split()
    
    if not reference_tokens or not candidate_tokens:
        return 0.0
    
    return sentence_bleu([reference_tokens], candidate_tokens, smoothing_function=smoothing)

def calculate_rouge(reference: str, candidate: str) -> Dict[str, float]:
    """Calculate ROUGE-L scores"""
    if not reference or not candidate:
        return {'precision': 0.0, 'recall': 0.0, 'fmeasure': 0.0}
    
    scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
    scores = scorer.score(reference, candidate)
    
    return {
        'precision': scores['rougeL'].precision,
        'recall': scores['rougeL'].recall,
        'fmeasure': scores['rougeL'].fmeasure
    }

def evaluate_policy_against_reference(policy: Dict[str, str], reference: Dict[str, str]) -> Dict:
    """Evaluate a single policy against its reference template"""
    results = {}
    
    # Evaluate implementation section
    impl_bleu = calculate_bleu(
        reference.get('implementation', ''),
        policy.get('implementation', '')
    )
    impl_rouge = calculate_rouge(
        reference.get('implementation', ''),
        policy.get('implementation', '')
    )
    
    results['implementation_bleu'] = impl_bleu
    results['implementation_rouge_l_precision'] = impl_rouge['precision']
    results['implementation_rouge_l_recall'] = impl_rouge['recall']
    results['implementation_rouge_l_fmeasure'] = impl_rouge['fmeasure']
    
    # Evaluate verification section
    verif_bleu = calculate_bleu(
        reference.get('verification', ''),
        policy.get('verification', '')
    )
    verif_rouge = calculate_rouge(
        reference.get('verification', ''),
        policy.get('verification', '')
    )
    
    results['verification_bleu'] = verif_bleu
    results['verification_rouge_l_precision'] = verif_rouge['precision']
    results['verification_rouge_l_recall'] = verif_rouge['recall']
    results['verification_rouge_l_fmeasure'] = verif_rouge['fmeasure']
    
    # Check NIST CSF compliance
    policy_nist = policy.get('nist_csf', '').strip()
    ref_nist = reference.get('nist_csf', '').strip()
    results['nist_csf_match'] = (policy_nist == ref_nist) if policy_nist and ref_nist else False
    
    # Check ISO 27001 compliance
    policy_iso = policy.get('iso_27001', '').strip()
    ref_iso = reference.get('iso_27001', '').strip()
    results['iso_27001_match'] = (policy_iso == ref_iso) if policy_iso and ref_iso else False
    
    # Calculate overall score (average of all metrics)
    numeric_scores = [
        impl_bleu,
        impl_rouge['fmeasure'],
        verif_bleu,
        verif_rouge['fmeasure']
    ]
    results['overall_score'] = sum(numeric_scores) / len(numeric_scores) if numeric_scores else 0.0
    
    return results

def calculate_accuracy(results: List[Dict], threshold: float = 0.3) -> Dict:
    """
    Calculate accuracy metrics based on BLEU/ROUGE-L thresholds
    
    Args:
        results: List of evaluation results
        threshold: Minimum score to consider a policy as "accurate"
    
    Returns:
        Dictionary with accuracy metrics
    """
    if not results:
        return {
            'overall_accuracy': 0.0,
            'implementation_accuracy': 0.0,
            'verification_accuracy': 0.0,
            'policies_above_threshold': 0,
            'total_policies': 0,
            'threshold_used': threshold
        }
    
    total = len(results)
    
    # Count policies above threshold for each component
    implementation_accurate = sum(
        1 for r in results 
        if r.get('implementation_rouge_l_fmeasure', 0) >= threshold
    )
    verification_accurate = sum(
        1 for r in results 
        if r.get('verification_rouge_l_fmeasure', 0) >= threshold
    )
    
    # Count policies with overall score above threshold
    overall_accurate = sum(
        1 for r in results 
        if r.get('overall_score', 0) >= threshold
    )
    
    return {
        'overall_accuracy': (overall_accurate / total) * 100,
        'implementation_accuracy': (implementation_accurate / total) * 100,
        'verification_accuracy': (verification_accurate / total) * 100,
        'policies_above_threshold': overall_accurate,
        'total_policies': total,
        'threshold_used': threshold
    }

def calculate_averages(results: List[Dict]) -> Dict:
    """Calculate aggregate statistics including accuracy"""
    if not results:
        return {}
    
    # Calculate averages for BLEU and ROUGE-L scores
    avg_impl_bleu = sum(r.get('implementation_bleu', 0) for r in results) / len(results)
    avg_impl_rouge = sum(r.get('implementation_rouge_l_fmeasure', 0) for r in results) / len(results)
    avg_verif_bleu = sum(r.get('verification_bleu', 0) for r in results) / len(results)
    avg_verif_rouge = sum(r.get('verification_rouge_l_fmeasure', 0) for r in results) / len(results)
    avg_overall = sum(r.get('overall_score', 0) for r in results) / len(results)
    
    # Calculate compliance rates
    nist_compliance = sum(1 for r in results if r.get('nist_csf_match', False)) / len(results) * 100
    iso_compliance = sum(1 for r in results if r.get('iso_27001_match', False)) / len(results) * 100
    
    # Calculate accuracy metrics
    accuracy_metrics = calculate_accuracy(results, threshold=0.3)
    
    return {
        'avg_statement_bleu': 0.0,  # Not evaluated in current implementation
        'avg_statement_rouge_l': 0.0,  # Not evaluated in current implementation
        'avg_implementation_bleu': avg_impl_bleu,
        'avg_implementation_rouge_l': avg_impl_rouge,
        'avg_verification_bleu': avg_verif_bleu,
        'avg_verification_rouge_l': avg_verif_rouge,
        'avg_overall_score': avg_overall,
        'nist_csf_compliance_rate': nist_compliance,
        'iso_27001_compliance_rate': iso_compliance,
        # Add accuracy metrics
        'overall_accuracy': accuracy_metrics['overall_accuracy'],
        'implementation_accuracy': accuracy_metrics['implementation_accuracy'],
        'verification_accuracy': accuracy_metrics['verification_accuracy'],
        'policies_above_threshold': accuracy_metrics['policies_above_threshold'],
        'accuracy_threshold': accuracy_metrics['threshold_used']
    }

def main():
    """Main evaluation function"""
    print("\n" + "="*70)
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
      
    # Calculate aggregate statistics with accuracy  
    deepseek_summary = calculate_averages(deepseek_results)  
    llama_summary = calculate_averages(llama_results)  
      
    # Prepare final report  
    final_report = {  
        'evaluation_metadata': {  
            'evaluation_type': 'Generated Policies vs NIST/ISO Reference Templates',  
            'metrics_used': ['BLEU', 'ROUGE-L', 'Accuracy'],  
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
    if deepseek_summary.get('avg_implementation_bleu', 0) > llama_summary.get('avg_implementation_bleu', 0):  
        final_report['comparative_analysis']['deepseek_advantages'].append('Better implementation quality (BLEU)')  
    else:  
        final_report['comparative_analysis']['llama_advantages'].append('Better implementation quality (BLEU)')  
      
    if deepseek_summary.get('overall_accuracy', 0) > llama_summary.get('overall_accuracy', 0):  
        final_report['comparative_analysis']['deepseek_advantages'].append('Higher overall accuracy')  
    else:  
        final_report['comparative_analysis']['llama_advantages'].append('Higher overall accuracy')  
      
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
    print(f"  Overall Accuracy: {deepseek_summary.get('overall_accuracy', 0):.1f}%")  
    print(f"  Implementation Accuracy: {deepseek_summary.get('implementation_accuracy', 0):.1f}%")  
    print(f"  Verification Accuracy: {deepseek_summary.get('verification_accuracy', 0):.1f}%")  
    print(f"  Implementation BLEU: {deepseek_summary.get('avg_implementation_bleu', 0):.4f}")  
    print(f"  Verification BLEU: {deepseek_summary.get('avg_verification_bleu', 0):.4f}")  
    print(f"  NIST CSF Compliance: {deepseek_summary.get('nist_csf_compliance_rate', 0):.1f}%")  
    print(f"  ISO 27001 Compliance: {deepseek_summary.get('iso_27001_compliance_rate', 0):.1f}%")  
    print(f"  Policies above threshold ({deepseek_summary.get('accuracy_threshold', 0.3)}): {deepseek_summary.get('policies_above_threshold', 0)}/{len(deepseek_results)}")  
      
    print(f"\n🦙 LLaMA Results:")  
    print(f"  Overall Score: {llama_summary.get('avg_overall_score', 0):.4f}")  
    print(f"  Overall Accuracy: {llama_summary.get('overall_accuracy', 0):.1f}%")  
    print(f"  Implementation Accuracy: {llama_summary.get('implementation_accuracy', 0):.1f}%")  
    print(f"  Verification Accuracy: {llama_summary.get('verification_accuracy', 0):.1f}%")  
    print(f"  Implementation BLEU: {llama_summary.get('avg_implementation_bleu', 0):.4f}")  
    print(f"  Verification BLEU: {llama_summary.get('avg_verification_bleu', 0):.4f}")  
    print(f"  NIST CSF Compliance: {llama_summary.get('nist_csf_compliance_rate', 0):.1f}%")  
    print(f"  ISO 27001 Compliance: {llama_summary.get('iso_27001_compliance_rate', 0):.1f}%")  
    print(f"  Policies above threshold ({llama_summary.get('accuracy_threshold', 0.3)}): {llama_summary.get('policies_above_threshold', 0)}/{len(llama_results)}")  
      
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