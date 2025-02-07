import os
import sys
sys.path.insert(0, os.path.abspath('../..'))

project = 'Packet Sniffer'
copyright = '2025, Ajinkya Shetty'
author = 'Ajinkya Shetty'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',    
    'sphinx.ext.napoleon',  
    'rst2pdf.pdfbuilder'     ]

autodoc_typehints = "description" 


templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
