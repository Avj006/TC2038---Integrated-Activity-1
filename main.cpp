/*
Program: TC2038.601
Activity: Transmission Analysis Tool (Actividad Integradora 1.2)
Authors: Angela Andrea Castro García A01640019 & Andrea Villaseñor Jiménez A01642088
Date: Friday, September 11th, 2026
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>

using namespace std;

/*
Description:
  Reads five text files (transmission1.txt, transmission2.txt, mcode1.txt, 
  mcode2.txt, mcode3.txt) containing hexadecimal characters (0-9, A-F) 
  and line breaks. Performs three distinct non-sequential analysis tasks:
    - Part 1 (Stage 1): Substring search using KMP algorithm.
    - Part 2 (Stage 2): Longest palindromic substring search using Manacher's algorithm.
    - Part 3 (Stage 3): Longest Common Substring (LCS) search using Dynamic Programming.

Preconditions:
  - The 5 text files exist in the same execution root directory.
  - Inputs contain valid hexadecimal characters and line breaks.

Inputs:
  - 5 text files (no standard console input).

Outputs:
  - Part 1: 6 lines formatted as "(true position | false)".
  - Part 2: 2 lines displaying "startPosition endPosition" for each transmission.
  - Part 3: 1 line displaying "startPosition endPosition" relative to transmission1.txt.
*/

*/

/*
Function: readFile

Purpose:
  Reads a text file line by line and concatenates its contents into a 
  single contiguous std::string, stripping all newline (\n) and carriage 
  return (\r) characters.

Parameters:
  - fileName (const string&): Name or path of the target text file.

Return Value:
  - string: Single string containing the file's character sequence.

Preconditions:
  - Specified file exists and has read permissions.

Postconditions:
  - File stream is properly closed; file content remains unmodified.

Complexity:
  - Time Complexity : O(N), where N is total characters in the file.
  - Space Complexity: O(N), to store file content in memory.
*/
string readFile(const string& fileName) {
    ifstream file(fileName);
    string content = "";
    string line = "";

    while (getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        content = content + line;
    }

    return content;
}

/*
Function: computeLps

Purpose:
  Computes the Longest Proper Prefix which is also Suffix (LPS) array for 
  the malicious code pattern to optimize pattern matching in KMP.

Parameters:
  - pattern (const string&): Malicious code pattern sequence to preprocess.

Return Value:
  - vector<int>: Array containing the length of the longest proper prefix 
    that is also a suffix for each prefix of the pattern.

Complexity:
  - Time Complexity : O(M), where M is the length of the pattern.
  - Space Complexity: O(M), to store the LPS array.
*/
vector<int> computeLps(const string& pattern) {
    int patternLength = static_cast<int>(pattern.length());
    vector<int> lps(patternLength, 0);
    int length = 0;
    int index = 1;

    while (index < patternLength) {
        if (pattern[index] == pattern[length]) {
            length = length + 1;
            lps[index] = length;
            index = index + 1;
        } else {
            if (length != 0) {
                length = lps[length - 1];
            } else {
                lps[index] = 0;
                index = index + 1;
            }
        }
    }

    return lps;
}

/*
Function: computeLps

Purpose:
  Searches for the first occurrence of a malicious code pattern (mcode) inside 
  a transmission string using the Knuth-Morris-Pratt (KMP) algorithm.

Parameters:
  - text (const string&): Transmission content string.
  - pattern (const string&): Malicious code pattern sequence.

Return Value:
  - int: 1-indexed starting position if found, or 0 if not present.

Preconditions:
  - Both input strings are non-null and initialized.

Postconditions:
  - Returns positive 1-indexed position if matched, else 0.

Complexity:
  - Time Complexity : O(N + M), where N = text.length(), M = pattern.length().
  - Space Complexity: O(M) auxiliary space for the LPS array.
*/
int findMaliciousCodePosition(const string& text, const string& pattern) {
    int textLength = static_cast<int>(text.length());
    int patternLength = static_cast<int>(pattern.length());
    int foundPosition = 0;

    if (patternLength == 0 || textLength < patternLength) {
        return foundPosition;
    }

    vector<int> lps = computeLps(pattern);
    int textIndex = 0;
    int patternIndex = 0;
    bool patternFound = false;

    while (textIndex < textLength && !patternFound) {
        if (text[textIndex] == pattern[patternIndex]) {
            textIndex = textIndex + 1;
            patternIndex = patternIndex + 1;

            if (patternIndex == patternLength) {
                foundPosition = textIndex - patternLength + 1;
                patternFound = true;
            }
        } else {
            if (patternIndex != 0) {
                patternIndex = lps[patternIndex - 1];
            } else {
                textIndex = textIndex + 1;
            }
        }
    }

    return foundPosition;
}

/*
Function: displaySearchResult

Purpose:
  Prints the formatted search result for a malicious code pattern within a transmission.
  Outputs "true <position>" if found, or "false" if not found.

Parameters:
  - position (int): 1-indexed start position of the match, or 0 if not present.

Return Value:
  - void.
*/
void displaySearchResult(int position) {
    if (position > 0) {
        cout << "true " << position << "\n";
    } else {
        cout << "false\n";
    }
}

/*
Function: displaySearchResult

Purpose:
  Prints the formatted search result for a malicious code pattern within a transmission.
  Outputs "true <position>" if found, or "false" if not found.

Parameters:
  - position (int): 1-indexed start position of the match, or 0 if not present.

Return Value:
  - void.

Preconditions:
  - Position parameter is non-negative.

Postconditions:
  - Prints result to standard output stream.

Complexity:
  - Time Complexity : O(1).
  - Space Complexity: O(1).
*/
void displaySearchResult(int position) {
    if (position > 0) {
        cout << "true " << position << "\n";
    } else {
        cout << "false\n";
    }
}

/* ============================================================================
   STAGE 2 (PART 2): LONGEST PALINDROMIC SUBSTRING (MANACHER'S ALGORITHM)
   ============================================================================ */

/*
Function: findLongestPalindrome

Purpose:
  Finds the longest contiguous palindromic substring ("mirrored" code) 
  within a transmission string using dynamic programming.

Parameters:
  - transmission (const string&): Transmission content string.

Return Value:
  - pair<int, int>: 1-indexed (startPosition, endPosition) of the 
    longest palindrome found.
*/
pair<int, int> findLongestPalindrome(const string& transmission) {
    int string_lenght = transmission.size();
    
    if (string_lenght == 0) return {0, 0}; 

    // String preparation with spacer #
    string temp_string = "#";
    for (char c : transmission) {
        temp_string += c;
        temp_string += "#";
    }
    
    // p_array must have the length of the transformed string
    vector<int> p_array(temp_string.size(), 0);

    
    int palindrome_center = 0; // Corresponds to c in the pseudocode presented in class
    int right_limit = 0;       // Corresponds to r in the pseudocode presented in class
    int current_index;         // Corresponds to i in the loop; in the pseudocode presented in class
    int current_index_mirrored;// Corresponds to i' in the pseudocode presented in class

    // Return variables
    int startPosition = 0;
    int endPosition = 0;

    // --- Your for loop starts here using 'current_index' instead of 'i' ---
    // for(current_index = 1; current_index < temp_string.size() - 1; current_index++) { ... }
    for(current_index = 1; current_index < temp_string.size() - 1; current_index++){
        current_index_mirrored = 2 * palindrome_center - current_index;
        
        if(right_limit > current_index){
            // Corrección: r - i
            p_array[current_index] = min(right_limit - current_index, p_array[current_index_mirrored]);
        } else {
            p_array[current_index] = 0;
        }
        
        // Corrección: Usar temp_string, arreglar corchetes, nombrar bien p_array y proteger límites
        while (current_index - 1 - p_array[current_index] >= 0 && 
               current_index + 1 + p_array[current_index] < temp_string.size() &&
               temp_string[current_index + 1 + p_array[current_index]] == temp_string[current_index - 1 - p_array[current_index]]) {
            
            p_array[current_index] += 1;
        }
        
        if(current_index + p_array[current_index] > right_limit){
            palindrome_center = current_index;
            right_limit = current_index + p_array[current_index]; // Corrección: faltaba ';'
        }
    }

    //extra logic to return first position and last (start and end)
    int max_lenght_palindome = 0;
    int center_index = 0;

    for (int i = 0; i < p_array.size(); i++) {
        if (p_array[i] > max_lenght_palindome) {
            max_lenght_palindome = p_array[i];
            center_index = i;
        }
    }
    startPosition = (center_index - max_lenght_palindome) / 2; //due to the # characters
    endPosition = startPosition + max_lenght_palindome - 1;

    return {startPosition, endPosition};
}

/*
Function: findLongestCommonSubstring

Purpose:
  Calculates the Longest Common Substring (LCS) between two transmission 
  files using Dynamic Programming, tracking start and end coordinates 
  relative to transmission1.txt.

Parameters:
  - trans1 (const string&): Content of transmission1.txt.
  - trans2 (const string&): Content of transmission2.txt.

Return Value:
  - pair<int, int>: 1-indexed (startPosition, endPosition) of the LCS 
    in transmission1.txt.

Preconditions:
  - Both transmission strings are loaded in memory.

Postconditions:
  - Returns 1-indexed boundaries mapping exclusively to trans1.

Complexity:
  - Time Complexity : O(M * N), where M = trans1.length(), N = trans2.length().
  - Space Complexity: O(M * N) for the 2D Dynamic Programming matrix.
*/
pair<int, int> findLongestCommonSubstring(const string& trans1, const string& trans2) {
    int length1 = static_cast<int>(trans1.length());
    int length2 = static_cast<int>(trans2.length());
    pair<int, int> result = {0, 0};

    if (length1 == 0 || length2 == 0) {
        return result;
    }

    vector<vector<int>> dp(length1 + 1, vector<int>(length2 + 1, 0));
    int maxLength = 0;
    int endIndexTrans1 = 0;
    int i = 1;

    while (i <= length1) {
        int j = 1;

        while (j <= length2) {
            if (trans1[i - 1] == trans2[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1] + 1;

                if (dp[i][j] > maxLength) {
                    maxLength = dp[i][j];
                    endIndexTrans1 = i;
                }
            } else {
                dp[i][j] = 0;
            }
            j = j + 1;
        }
        i = i + 1;
    }

    if (maxLength > 0) {
        result.first = endIndexTrans1 - maxLength + 1;
        result.second = endIndexTrans1;
    }

    return result;
}


/*
Function: main

Purpose:
  Program entry point. Coordinates reading all 5 text files, triggers 
  execution of analysis modules for Stage 1 (Part 1), Stage 2 (Part 2), 
  and Stage 3 (Part 3), formatting output according to specifications.

Parameters:
  - None.

Return Value:
  - int: 0 upon successful execution.

Preconditions:
  - The 5 required text files exist in the execution path.

Postconditions:
  - Outputs analysis results strictly in the required format.
*/
int main() {
    // Reading the 5 text files
    string transmission1 = readFile("transmission1.txt");
    string transmission2 = readFile("transmission2.txt");
    string mcode1 = readFile("mcode1.txt");
    string mcode2 = readFile("mcode2.txt");
    string mcode3 = readFile("mcode3.txt");

    
    // Part 1: Search mcode1, mcode2, mcode3 in transmission1.txt
    displaySearchResult(findMaliciousCodePosition(transmission1, mcode1));
    displaySearchResult(findMaliciousCodePosition(transmission1, mcode2));
    displaySearchResult(findMaliciousCodePosition(transmission1, mcode3));

    // Part 1: Search mcode1, mcode2, mcode3 in transmission2.txt
    displaySearchResult(findMaliciousCodePosition(transmission2, mcode1));
    displaySearchResult(findMaliciousCodePosition(transmission2, mcode2));
    displaySearchResult(findMaliciousCodePosition(transmission2, mcode3));
    

    // Part 2: Longest palindrome in transmission1 and transmission2 (placeholder)
    pair<int, int> palindromeTrans1 = findLongestPalindrome(transmission1);
    cout << palindromeTrans1.first + 1 << " " << palindromeTrans1.second + 1 << "\n";
    pair<int, int> palindromeTrans2 = findLongestPalindrome(transmission2);
    cout << palindromeTrans2.first + 1 << " " << palindromeTrans2.second + 1 << "\n";

    // Part 3: Longest Common Substring in transmission1 relative to transmission2 (placeholder)
    pair<int, int> lcsResult = findLongestCommonSubstring(transmission1, transmission2);
    cout << lcsResult.first << " " << lcsResult.second << "\n";

    return 0;
}
