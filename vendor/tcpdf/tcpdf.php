<?php
/**
 * Lightweight Standalone TCPDF-Compatible PDF Engine
 * 
 * PILLAR B [B3]: STATEMENT EXPORT (PDF)
 * 
 * Provides standard TCPDF API methods without external binaries or composer dependencies:
 * - AddPage, SetFont, Cell, SetTextColor, SetDrawColor, SetFillColor, Line, Rect, Output
 * 
 * Generates compliant PDF 1.4 streams with proper xref table and catalog dictionary.
 */

class TCPDF {
    protected int $page = 0;
    protected int $n = 2; // object count
    protected array $offsets = [];
    protected string $buffer = '';
    protected array $pages = [];
    protected int $state = 0;
    protected string $fontFamily = 'Helvetica';
    protected string $fontStyle = '';
    protected float $fontSizePt = 12.0;
    protected float $fontSize = 4.23; // mm
    protected float $x = 15.0;
    protected float $y = 15.0;
    protected float $lMargin = 15.0;
    protected float $tMargin = 15.0;
    protected float $rMargin = 15.0;
    protected float $bMargin = 15.0;
    protected float $w = 210.0; // A4 width mm
    protected float $h = 297.0; // A4 height mm
    protected float $k = 2.83464566929; // points per mm (72 / 25.4)
    protected string $drawColor = '0 0 0 RG';
    protected string $fillColor = '0 0 0 rg';
    protected string $textColor = '0 0 0 rg';

    public function __construct(string $orientation = 'P', string $unit = 'mm', string $format = 'A4') {
        $this->page = 0;
        $this->n = 2;
        $this->buffer = '';
        $this->pages = [];
        $this->w = 210.0;
        $this->h = 297.0;
    }

    public function SetMargins(float $left, float $top, float $right = 15.0): void {
        $this->lMargin = $left;
        $this->tMargin = $top;
        $this->rMargin = $right;
    }

    public function AddPage(): void {
        $this->page++;
        $this->pages[$this->page] = '';
        $this->x = $this->lMargin;
        $this->y = $this->tMargin;
    }

    public function SetFont(string $family, string $style = '', float $size = 12.0): void {
        $family = strtolower($family);
        if ($family === '' || $family === 'arial') {
            $family = 'helvetica';
        }
        $this->fontFamily = ucfirst($family);
        $this->fontStyle = strtoupper($style);
        $this->fontSizePt = $size;
        $this->fontSize = $size / $this->k;
    }

    public function SetTextColor(int $r, int $g = -1, int $b = -1): void {
        if ($g === -1 && $b === -1) {
            $this->textColor = sprintf('%.3F g', $r / 255.0);
        } else {
            $this->textColor = sprintf('%.3F %.3F %.3F rg', $r / 255.0, $g / 255.0, $b / 255.0);
        }
    }

    public function SetDrawColor(int $r, int $g = -1, int $b = -1): void {
        if ($g === -1 && $b === -1) {
            $this->drawColor = sprintf('%.3F G', $r / 255.0);
        } else {
            $this->drawColor = sprintf('%.3F %.3F %.3F RG', $r / 255.0, $g / 255.0, $b / 255.0);
        }
    }

    public function SetFillColor(int $r, int $g = -1, int $b = -1): void {
        if ($g === -1 && $b === -1) {
            $this->fillColor = sprintf('%.3F g', $r / 255.0);
        } else {
            $this->fillColor = sprintf('%.3F %.3F %.3F rg', $r / 255.0, $g / 255.0, $b / 255.0);
        }
    }

    public function SetLineWidth(float $width): void {
        $this->out(sprintf('%.2F w', $width * $this->k));
    }

    public function Line(float $x1, float $y1, float $x2, float $y2): void {
        $this->out(sprintf(
            '%s %.2F %.2F m %.2F %.2F l S',
            $this->drawColor,
            $x1 * $this->k,
            ($this->h - $y1) * $this->k,
            $x2 * $this->k,
            ($this->h - $y2) * $this->k
        ));
    }

    public function Rect(float $x, float $y, float $w, float $h, string $style = ''): void {
        $op = 'S';
        if ($style === 'F') $op = 'f';
        elseif ($style === 'FD' || $style === 'DF') $op = 'B';

        $cmd = ($op === 'f' || $op === 'B') ? $this->fillColor . ' ' : '';
        if ($op === 'S' || $op === 'B') $cmd .= $this->drawColor . ' ';

        $cmd .= sprintf('%.2F %.2F %.2F %.2F re %s',
            $x * $this->k,
            ($this->h - $y - $h) * $this->k,
            $w * $this->k,
            $h * $this->k,
            $op
        );
        $this->out($cmd);
    }

    public function Cell(float $w, float $h = 0, string $txt = '', $border = 0, int $ln = 0, string $align = '', bool $fill = false): void {
        $k = $this->k;
        if ($this->y + $h > $this->h - $this->bMargin) {
            $this->AddPage();
        }
        if ($w == 0) {
            $w = $this->w - $this->rMargin - $this->x;
        }

        $s = '';
        if ($fill || $border == 1) {
            $op = '';
            if ($fill) {
                $op = ($border == 1) ? 'B' : 'f';
            } elseif ($border == 1) {
                $op = 'S';
            }
            if ($fill) $s .= $this->fillColor . ' ';
            if ($border == 1) $s .= $this->drawColor . ' ';
            $s .= sprintf('%.2F %.2F %.2F %.2F re %s ',
                $this->x * $k,
                ($this->h - $this->y - $h) * $k,
                $w * $k,
                $h * $k,
                $op
            );
        }

        if (is_string($border)) {
            $x = $this->x;
            $y = $this->y;
            $s .= $this->drawColor . ' ';
            if (str_contains($border, 'L')) $s .= sprintf('%.2F %.2F m %.2F %.2F l S ', $x * $k, ($this->h - $y) * $k, $x * $k, ($this->h - ($y + $h)) * $k);
            if (str_contains($border, 'T')) $s .= sprintf('%.2F %.2F m %.2F %.2F l S ', $x * $k, ($this->h - $y) * $k, ($x + $w) * $k, ($this->h - $y) * $k);
            if (str_contains($border, 'R')) $s .= sprintf('%.2F %.2F m %.2F %.2F l S ', ($x + $w) * $k, ($this->h - $y) * $k, ($x + $w) * $k, ($this->h - ($y + $h)) * $k);
            if (str_contains($border, 'B')) $s .= sprintf('%.2F %.2F m %.2F %.2F l S ', $x * $k, ($this->h - ($y + $h)) * $k, ($x + $w) * $k, ($this->h - ($y + $h)) * $k);
        }

        if ($txt !== '') {
            $fontName = ($this->fontStyle === 'B') ? 'F2' : 'F1';
            $escaped = str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $txt);
            
            // X alignment calculation
            $dx = 1.5;
            if ($align === 'R') {
                $dx = $w - ($this->GetStringWidth($txt) + 1.5);
            } elseif ($align === 'C') {
                $dx = ($w - $this->GetStringWidth($txt)) / 2.0;
            }

            $s .= sprintf('BT /%s %.2F Tf %s %.2F %.2F Td (%s) Tj ET ',
                $fontName,
                $this->fontSizePt,
                $this->textColor,
                ($this->x + $dx) * $k,
                ($this->h - ($this->y + 0.5 * $h + 0.3 * $this->fontSize)) * $k,
                $escaped
            );
        }

        if ($s) {
            $this->out($s);
        }

        if ($ln > 0) {
            $this->y += $h;
            $this->x = $this->lMargin;
        } else {
            $this->x += $w;
        }
    }

    public function Ln(float $h = 0): void {
        $this->x = $this->lMargin;
        $this->y += ($h == 0) ? $this->fontSize : $h;
    }

    public function GetStringWidth(string $s): float {
        // Approximate proportional width for standard Helvetica (0.55 of pt size in mm)
        return strlen($s) * ($this->fontSizePt * 0.55 / $this->k);
    }

    public function SetXY(float $x, float $y): void {
        $this->x = $x;
        $this->y = $y;
    }

    public function GetX(): float {
        return $this->x;
    }

    public function GetY(): float {
        return $this->y;
    }

    protected function out(string $s): void {
        if ($this->page > 0) {
            $this->pages[$this->page] .= $s . "\n";
        } else {
            $this->buffer .= $s . "\n";
        }
    }

    public function Output(string $name = 'doc.pdf', string $dest = 'I'): string {
        // Build complete PDF 1.4 document
        $pdf = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";

        // Object 1: Catalog
        $o1 = strlen($pdf);
        $pdf .= "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

        // Pages array
        $kids = [];
        $pageObjIds = [];
        $contentObjIds = [];
        $nextObjId = 7;

        for ($i = 1; $i <= $this->page; $i++) {
            $pageObjIds[$i] = $nextObjId++;
            $contentObjIds[$i] = $nextObjId++;
            $kids[] = "{$pageObjIds[$i]} 0 R";
        }

        // Object 2: Pages container
        $o2 = strlen($pdf);
        $pdf .= "2 0 obj\n<< /Type /Pages /Kids [" . implode(' ', $kids) . "] /Count " . $this->page . " >>\nendobj\n";

        // Fonts
        // Object 3: Helvetica Regular
        $o3 = strlen($pdf);
        $pdf .= "3 0 obj\n<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n";

        // Object 4: Helvetica Bold
        $o4 = strlen($pdf);
        $pdf .= "4 0 obj\n<< /Type /Font /Subtype /Type1 /Name /F2 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n";

        $objOffsets = [1 => $o1, 2 => $o2, 3 => $o3, 4 => $o4];

        for ($i = 1; $i <= $this->page; $i++) {
            $pId = $pageObjIds[$i];
            $cId = $contentObjIds[$i];
            $content = $this->pages[$i];

            // Page Object
            $objOffsets[$pId] = strlen($pdf);
            $pdf .= "$pId 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Contents $cId 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>\nendobj\n";

            // Content Stream Object
            $objOffsets[$cId] = strlen($pdf);
            $pdf .= "$cId 0 obj\n<< /Length " . strlen($content) . " >>\nstream\n" . $content . "endstream\nendobj\n";
        }

        // Xref table
        $totalObjs = $nextObjId;
        $xrefOffset = strlen($pdf);
        $pdf .= "xref\n0 $totalObjs\n0000000000 65535 f \n";

        for ($i = 1; $i < $totalObjs; $i++) {
            $off = $objOffsets[$i] ?? 0;
            $pdf .= sprintf("%010d 00000 n \n", $off);
        }

        // Trailer
        $pdf .= "trailer\n<< /Size $totalObjs /Root 1 0 R >>\nstartxref\n$xrefOffset\n%%EOF\n";

        if ($dest === 'S') {
            return $pdf;
        }

        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . basename($name) . '"');
        header('Content-Length: ' . strlen($pdf));
        echo $pdf;
        return $pdf;
    }
}
