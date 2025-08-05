import logging
import sys
import os
from datetime import datetime
from typing import List

# Define the log file path
log_file = "/var/log/virusCleaner.log"

# Configure logging with basic format
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

try:
    log_handler = logging.FileHandler(log_file)
    log_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
except PermissionError:
    print("Error: Permission denied. Please run the script with sudo.", file=sys.stderr)
    sys.exit(1)  # Exit the script to enforce sudo usage


def log_info(message: str) -> None:
    """Log general information to both the console and log file."""
    logger.info(message)

def log_error(message: str) -> None:
    """Log error message to both the console and log file."""
    logger.error(message)

def log_warning(message: str) -> None:
    """Log warning message to both the console and log file."""
    logger.warning(message)

def generate_session_pdf(session_logs: List[str]) -> str:
    """
    Generate a PDF from session logs using built-in libraries only.
    
    Args:
        session_logs: List of log messages from the current session
    
    Returns:
        str: Path to the generated PDF file
    
    Raises:
        Exception: If PDF generation fails
    """
    try:
        # Create output directory if it doesn't exist
        output_dir = "/tmp/disk_cloner_logs"
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"disk_cloner_session_{timestamp}.pdf"
        pdf_path = os.path.join(output_dir, pdf_filename)
        
        # Create PDF using basic PDF structure
        _create_simple_pdf(
            pdf_path,
            "Disk Cloner - Session Log Report",
            session_logs,
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Log Entries: {len(session_logs)}"
        )
        
        log_info(f"Session log PDF generated successfully: {pdf_path}")
        return pdf_path
        
    except PermissionError as e:
        error_msg = f"Permission denied writing PDF to {output_dir}: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)
    except OSError as e:
        error_msg = f"OS error during PDF generation: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error during session PDF generation: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)

def generate_log_file_pdf() -> str:
    """
    Generate a PDF from the complete log file using built-in libraries only.
    
    Returns:
        str: Path to the generated PDF file
    
    Raises:
        Exception: If PDF generation fails
    """
    try:
        # Create output directory if it doesn't exist
        output_dir = "/tmp/disk_cloner_logs"
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"disk_cloner_complete_log_{timestamp}.pdf"
        pdf_path = os.path.join(output_dir, pdf_filename)
        
        # Read log file
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_lines = [line.strip() for line in f.readlines() if line.strip()]
        except UnicodeDecodeError:
            # Try with different encoding if UTF-8 fails
            with open(log_file, 'r', encoding='latin-1') as f:
                log_lines = [line.strip() for line in f.readlines() if line.strip()]
        
        # Create PDF using basic PDF structure
        _create_simple_pdf(
            pdf_path,
            "Disk Cloner - Complete Log File Report",
            log_lines,
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Log File: {log_file}",
            f"Total Log Lines: {len(log_lines)}"
        )
        
        log_info(f"Complete log file PDF generated successfully: {pdf_path}")
        return pdf_path
        
    except FileNotFoundError as e:
        error_msg = f"Log file not found: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)
    except PermissionError as e:
        error_msg = f"Permission denied: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)
    except OSError as e:
        error_msg = f"OS error during PDF generation: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)
    except UnicodeDecodeError as e:
        error_msg = f"Error reading log file - encoding issue: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error during complete log PDF generation: {str(e)}"
        log_error(error_msg)
        raise Exception(error_msg)

def _create_simple_pdf(file_path: str, title: str, content_lines: List[str], *info_lines: str) -> None:
    """
    Create a simple PDF file using basic PDF structure without external libraries.
    
    Args:
        file_path: Path where to save the PDF
        title: Title of the document
        content_lines: List of content lines to include
        *info_lines: Additional info lines to include in header
    """
    try:
        with open(file_path, 'wb') as f:
            # PDF Header
            f.write(b'%PDF-1.4\n')
            
            # Prepare content first to get accurate length
            content = _prepare_pdf_content(title, content_lines, *info_lines)
            content_bytes = content.encode('utf-8')
            content_length = len(content_bytes)
            
            # Track object positions for xref table
            object_positions = {}
            
            # Object 1: Catalog
            object_positions[1] = f.tell()
            catalog_obj = b'''1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
'''
            f.write(catalog_obj)
            
            # Object 2: Pages
            object_positions[2] = f.tell()
            pages_obj = b'''2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
'''
            f.write(pages_obj)
            
            # Object 3: Page
            object_positions[3] = f.tell()
            page_obj = b'''3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
>>
endobj
'''
            f.write(page_obj)
            
            # Object 4: Content Stream
            object_positions[4] = f.tell()
            content_obj = f'''4 0 obj
<<
/Length {content_length}
>>
stream
{content}
endstream
endobj
'''.encode('utf-8')
            f.write(content_obj)
            
            # Object 5: Font
            object_positions[5] = f.tell()
            font_obj = b'''5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Courier
>>
endobj
'''
            f.write(font_obj)
            
            # Cross-reference table
            xref_start = f.tell()
            f.write(b'xref\n')
            f.write(b'0 6\n')
            f.write(b'0000000000 65535 f \n')
            for i in range(1, 6):
                f.write(f'{object_positions[i]:010d} 00000 n \n'.encode())
            
            # Trailer
            trailer = f'''trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
{xref_start}
%%EOF
'''.encode('utf-8')
            f.write(trailer)
            
    except Exception as e:
        raise Exception(f"Error creating PDF structure: {str(e)}")

def _prepare_pdf_content(title: str, content_lines: List[str], *info_lines: str) -> str:
    """
    Prepare PDF content stream with proper formatting.
    
    Args:
        title: Document title
        content_lines: List of content lines
        *info_lines: Additional info lines
    
    Returns:
        str: Formatted PDF content stream
    """
    try:
        lines = []
        
        # Start content stream
        lines.append("BT")  # Begin text
        
        y_position = 750  # Start near top of page
        
        # Add title
        lines.append(f"50 {y_position} Td")  # Move to position
        lines.append("/F1 16 Tf")  # Larger font for title
        lines.append(f"({_escape_pdf_string(title)}) Tj")
        y_position -= 30
        
        # Add info lines
        lines.append("/F1 10 Tf")  # Smaller font for info
        for info_line in info_lines:
            lines.append(f"0 -{15} Td")  # Move down 15 points
            lines.append(f"({_escape_pdf_string(info_line)}) Tj")
            y_position -= 15
        
        y_position -= 20  # Extra space before content
        
        # Add content lines
        lines.append("/F1 8 Tf")  # Small font for content
        lines.append(f"0 -{20} Td")  # Move down 20 points
        
        if not content_lines:
            lines.append("(No content available.) Tj")
        else:
            line_number = 1
            for content_line in content_lines:
                if y_position < 50:  # Start new page if needed (simplified)
                    lines.append("ET")  # End text block
                    lines.append("BT")  # Begin new text block
                    lines.append("/F1 8 Tf")
                    lines.append("50 750 Td")
                    y_position = 750
                
                # Truncate very long lines to fit on page
                if len(content_line) > 85:
                    content_line = content_line[:82] + "..."
                
                numbered_line = f"{line_number:4d}: {content_line}"
                lines.append(f"0 -{12} Td")  # Move down 12 points
                lines.append(f"({_escape_pdf_string(numbered_line)}) Tj")
                y_position -= 12
                line_number += 1
        
        lines.append("ET")  # End text
        
        return "\n".join(lines)
        
    except Exception as e:
        raise Exception(f"Error preparing PDF content: {str(e)}")

def _escape_pdf_string(text: str) -> str:
    """
    Escape special characters in PDF strings.
    
    Args:
        text: Text to escape
    
    Returns:
        str: Escaped text safe for PDF
    """
    try:
        # Replace special PDF string characters
        text = str(text)
        text = text.replace('\\', '\\\\')  # Backslash must be first
        text = text.replace('(', '\\(')
        text = text.replace(')', '\\)')
        text = text.replace('\r', ' ')
        text = text.replace('\n', ' ')
        text = text.replace('\t', ' ')
        
        # Remove or replace non-printable characters
        cleaned_text = ""
        for char in text:
            if ord(char) >= 32 and ord(char) <= 126:
                cleaned_text += char
            else:
                cleaned_text += " "  # Replace with space
        
        return cleaned_text
        
    except Exception as e:
        return f"Error processing text: {str(e)}"