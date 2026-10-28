/**
 * Client-Side JavaScript Helpers
 * Provides interactive helper functions for the lab interface.
 */

// Quick-fill helper to insert test payloads into the input box
function fillInput(payload) {
  const input = document.getElementById('testInput');
  if (input) {
    input.value = payload;
    input.focus();
  }
}
