$(document).ready(function() {

  $('#generate').click(function(e) {
      e.preventDefault()
      $.ajax({
          url: '/getpref',
          type: 'GET',
          success: function(e) {
            var max = questions.length - e.length;
            var random = Math.floor(Math.random() * (max));
            for(var i = 0; i < e.length; i++){
              if(random < i)
                break;
              random++;
            }

            console.log(random)
            var yes = document.createElement("BUTTON");        // Create a <button> element
            var t = document.createTextNode("Yes");       // Create a text node
            yes.appendChild(t);                                // Append the text to <button>
            yes.onclick = function(){
              $.ajax({
                url: '/getpref',
                type: 'POST',
                data:{
                  data: JSON.stringify({
                  question: random,
                  response: "yes"
                })
              },
                success: function(e){

                }
              })
            };
            var no = document.createElement("BUTTON");        // Create a <button> element
            var t2 = document.createTextNode("No");       // Create a text node
            no.appendChild(t2);                                // Append the text to <button>
            no.onclick = function(){
              $.ajax({
                url: '/getpref',
                type: 'POST',
                data: {
                  data: JSON.stringify({
                  question: random,
                  response: "no"
                })
              },
                success: function(e){

                }
              })
            };
            document.getElementById("preference").innerHTML = "";
            if(typeof(questions[random]) != 'undefined'){
              console.log('wtf')
              document.getElementById("preference").append(questions[random]);
              document.getElementById("preference").appendChild(yes);
              document.getElementById("preference").appendChild(no);
            }
            else
              document.getElementById("preference").append("No more questions");

            }
      });
  });
});
