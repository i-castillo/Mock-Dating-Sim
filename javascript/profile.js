function uploadphoto(){
  $.ajax({
      url: '/getpref',
      type: 'GET',
      success: function(e) {

        }
})
}

function previewphoto(input){
  if (input.files && input.files[0]) {
     var reader = new FileReader();

     reader.onload = function (e) {
         $('#selectedImage').attr('src', e.target.result).width(210).height(210);
     };

     reader.readAsDataURL(input.files[0]);
 }
}
