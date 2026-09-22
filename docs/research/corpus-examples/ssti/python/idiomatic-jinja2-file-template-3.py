# Manufactured, representative of safe Jinja2 usage: templates are
# loaded by name from a FileSystemLoader-configured directory, never
# compiled from request data.
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates/"))


def render_show_page(show_title: str, episode_notes: str) -> str:
    template = env.get_template("show-page.html")  # fixed template name
    return template.render(title=show_title, notes=episode_notes)
