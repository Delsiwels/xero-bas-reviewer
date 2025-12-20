"""
DeepSeek API client for BAS review
"""
import os
import requests
import time
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

load_dotenv()


class DeepSeekClient:
    """Client for interacting with DeepSeek API"""

    def __init__(self):
        self.api_key = os.getenv('DEEPSEEK_API_KEY')
        self.api_url = os.getenv('DEEPSEEK_API_URL', 'https://api.deepseek.com/v1/chat/completions')
        self.model = os.getenv('DEEPSEEK_MODEL', 'deepseek-chat')
        self.max_retries = int(os.getenv('MAX_RETRIES', 3))
        self.timeout = int(os.getenv('TIMEOUT_SECONDS', 30))

        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY not found in environment variables")

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 2000
    ) -> Optional[str]:
        """
        Send a chat completion request to DeepSeek API

        Args:
            messages: List of message dictionaries with 'role' and 'content'
            temperature: Sampling temperature (lower = more focused)
            max_tokens: Maximum tokens in response

        Returns:
            Response content or None if failed
        """
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }

        payload = {
            'model': self.model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens
        }

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    result = response.json()
                    return result['choices'][0]['message']['content']
                elif response.status_code == 429:  # Rate limit
                    wait_time = 2 ** attempt  # Exponential backoff
                    print(f"Rate limited. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    print(f"API error: {response.status_code} - {response.text}")
                    if attempt < self.max_retries - 1:
                        time.sleep(1)

            except requests.exceptions.Timeout:
                print(f"Request timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(1)
            except Exception as e:
                print(f"Error calling DeepSeek API: {str(e)}")
                if attempt < self.max_retries - 1:
                    time.sleep(1)

        return None

    def review_transaction(self, transaction_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Review a single transaction using DeepSeek AI

        Args:
            transaction_data: Dictionary containing transaction details
            context: Additional context (chart of accounts, validation rules, etc.)

        Returns:
            Dictionary with review results
        """
        from prompts import create_review_prompt

        prompt = create_review_prompt(transaction_data, context)

        messages = [
            {
                'role': 'system',
                'content': 'You are an expert Australian tax accountant specializing in BAS and GST compliance. IGNORE GST calculation amounts - they are always correct. ONLY review: (1) Is the GST CODE appropriate for this transaction type? (2) Is the account coding correct? Flag if normal business items are coded as BAS Excluded or GST Free without justification.'
            },
            {
                'role': 'user',
                'content': prompt
            }
        ]

        response = self.chat_completion(messages)

        if response:
            return self._parse_review_response(response, transaction_data)
        else:
            return {
                'has_issues': False,
                'issues': [],
                'comments': 'Failed to review transaction',
                'severity': 'error'
            }

    def _parse_review_response(self, response: str, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the AI response into structured review results"""
        # Try to extract structured information from the response
        has_issues = any(keyword in response.lower() for keyword in [
            'issue', 'incorrect', 'wrong', 'mismatch', 'error', 'should be', 'review'
        ])

        return {
            'has_issues': has_issues,
            'issues': self._extract_issues(response),
            'comments': response.strip(),
            'severity': self._determine_severity(response),
            'transaction_id': transaction_data.get('id', ''),
            'description': transaction_data.get('description', '')
        }

    def _extract_issues(self, response: str) -> List[str]:
        """Extract specific issues from the response"""
        issues = []
        lines = response.lower().split('\n')

        issue_keywords = {
            'gst': 'GST Code Issue',
            'account': 'Account Coding Issue',
            'bas': 'BAS Box Mapping Issue',
            'amount': 'Amount Threshold Issue',
            'missing': 'Missing Information'
        }

        for keyword, issue_type in issue_keywords.items():
            if any(keyword in line for line in lines):
                issues.append(issue_type)

        return issues if issues else ['General Review Required']

    def _determine_severity(self, response: str) -> str:
        """Determine severity level from response"""
        response_lower = response.lower()

        if any(word in response_lower for word in ['critical', 'must', 'incorrect', 'wrong']):
            return 'high'
        elif any(word in response_lower for word in ['should', 'review', 'check', 'verify']):
            return 'medium'
        elif any(word in response_lower for word in ['consider', 'may', 'might']):
            return 'low'
        else:
            return 'info'
