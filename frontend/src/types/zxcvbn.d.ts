declare module 'zxcvbn' {
  export interface ZXCVBNResult {
    guesses: number;
    guesses_log10: number;
    crack_times_seconds: ZXCVBNAttackTime;
    crack_times_display: ZXCVBNAttackTime;
    score: 0 | 1 | 2 | 3 | 4;
    feedback: ZXCVBNFeedback;
    sequence: ZXCVBNSequence[];
    calc_time: number;
  }

  export interface ZXCVBNAttackTime {
    online_throttling_100_per_hour: string | number;
    online_no_throttling_10_per_second: string | number;
    offline_slow_hashing_1e4_per_second: string | number;
    offline_fast_hashing_1e10_per_second: string | number;
  }

  export interface ZXCVBNFeedback {
    warning: string;
    suggestions: string[];
  }

  export interface ZXCVBNSequence {
    pattern: string;
    i: number;
    j: number;
    token: string;
    matched_word?: string;
    rank?: number;
    dictionary_name?: string;
    reversed?: boolean;
    l33t?: boolean;
    sub?: Record<string, string>;
    sub_display?: string;
    guesses?: number;
    guesses_log10?: number;
    base_token?: string;
    base_guesses?: number;
    base_matches?: string;
    repeat_count?: number;
    sequence_name?: string;
    sequence_space?: number;
    ascending?: boolean;
    regex_name?: string;
    regex_match?: string[];
    date_separator?: string;
    day?: number;
    month?: number;
    year?: number;
    separator?: string;
    graph?: string;
    turns?: number;
    shifted_count?: number;
  }

  export default function zxcvbn(password: string, userInputs?: string[]): ZXCVBNResult;
}