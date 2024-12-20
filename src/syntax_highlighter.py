from pygments import highlight
from pygments.lexers import get_lexer_for_filename, ClassNotFound
from pygments.formatters import HtmlFormatter
import logging

class SyntaxHighlighter:
    @staticmethod
    def highlight_code(filename: str, code: str, style: str = 'monokai') -> str:
        """Highlight code using Pygments and return HTML formatted string."""
        try:
            lexer = get_lexer_for_filename(filename)
            formatter = HtmlFormatter(style=style)
            return highlight(code, lexer, formatter)
        except ClassNotFound:
            logging.error(f"No lexer found for file: {filename}. Returning unhighlighted code.")
            return code
        except Exception as e:
            logging.error(f"Error highlighting code from {filename}: {str(e)}")
            return code

    @staticmethod
    def save_highlighted_code(filename: str, code: str, output_file: str, style: str = 'monokai'):
        """Highlight code and save it to an HTML file."""
        highlighted_code = SyntaxHighlighter.highlight_code(filename, code, style)
        with open(output_file, 'w') as f:
            f.write(highlighted_code)
        logging.info(f"Highlighted code saved to {output_file}")
