function getMarkdownFilename() {
  const params = new URLSearchParams(window.location.search);
  return params.get("post");
}

const blogContainer = document.getElementById("blog-container");
const file = `blogs/${getMarkdownFilename()}`;

fetch(file)
  .then(res => {
    if (!res.ok) throw new Error("Blog not found");
    return res.text();
  })
  .then(md => {
    blogContainer.innerHTML = `
      <div class="markdown-body">
        ${marked.parse(md)}
      </div>
    `;
    
    // Apply syntax highlighting if available
    if (typeof hljs !== 'undefined') {
      document.querySelectorAll('pre code').forEach(hljs.highlightElement);
    }
  })
  .catch(err => {
    blogContainer.innerHTML = `
      <div class="error-message">
        <h2>Error Loading Post</h2>
        <p>${err.message}</p>
        <a href="blog.html" class="btn">
          Return to Blog
        </a>
      </div>
    `;
  });