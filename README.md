# CTF Writeups Blog - michaelelfauz

A modern, dark-themed Hugo blog for Capture The Flag writeups and cybersecurity content.

## 🌐 Live Site

Visit the blog at: [https://michaelelfauz.github.io/blog/](https://michaelelfauz.github.io/blog/)

## ✨ Features

- **Modern Dark Theme** - Dark navy blue aesthetic with Hugo Stack theme
- **CTF-Focused** - Optimized for technical writeups with code syntax highlighting
- **Responsive Design** - Works perfectly on all devices
- **Fast & Lightweight** - Static site generation with Hugo
- **Search Functionality** - Quick search through all posts
- **Categories & Tags** - Organized content with Write-Up and Blog categories
- **Reading Time** - Automatic calculation of reading time
- **Auto-Deployment** - GitHub Actions automatically deploys to GitHub Pages

## 🚀 Quick Start

### Prerequisites

- Hugo Extended v0.121.0 or higher
- Git

### Local Development

1. **Clone the repository:**
   ```bash
   git clone https://github.com/michaelelfauz/blog.git
   cd blog
   ```

2. **Initialize the theme submodule:**
   ```bash
   git submodule update --init --recursive
   ```

3. **Run the development server:**
   ```bash
   hugo server -D
   ```

4. **Open your browser:**
   Navigate to `http://localhost:1313/blog/`

## 📝 Creating New Content

### Create a New CTF Writeup

```bash
hugo new content/posts/my-writeup-name.md
```

This will create a new post with the pre-configured template including:
- Title
- Description
- Date
- Categories (Write-Up)
- Tags
- Challenge structure

### Create a New Blog Post

```bash
hugo new content/posts/my-blog-post.md
```

Then edit the frontmatter to change the category to `Blog`.

## 📁 Project Structure

```
blog/
├── .github/
│   └── workflows/
│       └── hugo.yml          # GitHub Actions deployment workflow
├── archetypes/
│   ├── default.md
│   └── posts.md              # Template for new posts
├── assets/
│   └── scss/
│       └── custom/
│           └── custom.scss   # Custom dark theme styles
├── content/
│   ├── posts/                # All blog posts and writeups
│   │   ├── my-first-writeup.md
│   │   └── first-post.md
│   └── about.md              # About page
├── static/
│   └── images/
│       └── avatar.png        # Profile avatar
├── themes/
│   └── hugo-theme-stack/     # Hugo Stack theme (submodule)
├── .gitignore
├── hugo.toml                 # Hugo configuration
└── README.md
```

## 🎨 Theme Customization

The site uses a custom dark navy color scheme defined in `assets/scss/custom/custom.scss`:

- **Background**: Dark navy blue (#1a1f2e)
- **Card Background**: Slightly lighter navy (#252b3b)
- **Accent Color**: Purple (#8b5cf6)
- **Text Color**: Light gray (#e5e7eb)

### Category Colors

- **Write-Up**: Pink/Purple gradient
- **Blog**: Gray

## 🏷️ Categories and Tags

### Categories

- `Write-Up` - CTF challenge writeups
- `Blog` - General blog posts and tutorials

### Tags

- `National` - National competitions
- `International` - International competitions
- `SHS` - SHS-related events
- `N2L` - N2L competitions
- `Individual` - Individual challenges
- `LastSeenIn2026` - LastSeenIn2026 event
- `Sbnthesis` - Sbnthesis competition

Add more tags as needed in your post frontmatter!

## 🔧 Configuration

Key settings in `hugo.toml`:

```toml
baseURL = 'https://michaelelfauz.github.io/blog/'
title = 'CTF Writeups - michaelelfauz'
theme = 'hugo-theme-stack'
```

### Syntax Highlighting

Code blocks use Monokai theme with line numbers, perfect for CTF writeups.

## 🚢 Deployment

The site automatically deploys to GitHub Pages when you push to the `main` branch.

### Manual Build

```bash
hugo --gc --minify
```

The site will be built to the `public/` directory.

## 📦 Dependencies

- **Hugo Extended** v0.121.0+
- **Hugo Stack Theme** - via git submodule

## 🤝 Contributing

Feel free to open issues or submit pull requests for improvements!

## 📄 License

This blog content is personal. The Hugo Stack theme has its own license.

## 🔗 Links

- **Blog**: [michaelelfauz.github.io/blog](https://michaelelfauz.github.io/blog/)
- **GitHub**: [github.com/michaelelfauz](https://github.com/michaelelfauz)
- **Hugo**: [gohugo.io](https://gohugo.io)
- **Hugo Stack Theme**: [github.com/CaiJimmy/hugo-theme-stack](https://github.com/CaiJimmy/hugo-theme-stack)

---

**Happy hacking and keep learning!** 🚀🔐

