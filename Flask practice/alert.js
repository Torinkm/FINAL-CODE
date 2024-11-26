var milliseconds = 3000;
// setTimeout(function () {
//   document.getElementById('alert').remove();
// }, milliseconds);

setTimeout(function () {
  var element = document.getElementById('alert');
  element.style.opacity = '0'; // Set opacity to 0 for fading effect
  setTimeout(function () {
    element.remove(); // Remove the element after the fade
  }, 1000); // Wait for 1 second (1000 milliseconds) for the fade to complete
}, milliseconds);

function confirmDelete(book_id) {
  if (confirm("Are you sure you want to delete this book?")) {
      window.location.href = "/delete/" + book_id;  // Include the book_id in the URL
  }
}