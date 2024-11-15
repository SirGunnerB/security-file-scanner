from pygments import highlight
from pygments.lexers import get_lexer_for_filename
from pygments.formatters import HtmlFormatter

class SyntaxHighlighter:
    @staticmethod
    def highlight_code(filename, code):
        try:
            lexer = get_lexer_for_filename(filename)
            formatter = HtmlFormatter(style='monokai')
            return highlight(code, lexer, formatter)
        except:
            return code 