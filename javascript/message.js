$(document).ready(function() {
  // Get the input field
  var input = document.getElementById("input");
  input.addEventListener("keyup", function(event) {
    // Cancel the default action, if needed
    event.preventDefault();
    // Number 13 is the "Enter" key on the keyboard
    if (event.keyCode === 13) {
      // Trigger the button element with a click
      document.getElementById("myForm").click();
    }
  });

  $('#myForm').click(function(e) {
      name = document.getElementById("myForm").value;
      msg = $("input").val();

      e.preventDefault()
      $.ajax({
          url: '/message',
          type: 'POST',
          data: {
              receiver: name,
              message: msg
          },
          success: function(e) {
            $("#input").val("");
            var mess = $("<p class='messagesender'></p>").text(e + ": " + msg);
            $(".messages").append(mess);
            var out = document.getElementById("poppy");
            out.scrollTop = out.scrollHeight - out.clientHeight;
            }
      });
  });

});
