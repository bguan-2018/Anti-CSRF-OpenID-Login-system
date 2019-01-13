
function validateFormField(elementId) {
  var formArray = $('#'+elementId).serializeArray();
  for (var i = 0; i < formArray.length; i++){
    if (!formArray[i]['value']) {
      alert(formArray[i]['name'] + ' field cannot be empty');
      return false;
    }
  }
  return true;
}

/*
 * This method parses the new event form into a json 
 */
function getFormJSON(elementId) {
  var formArray = $('#'+elementId).serializeArray();
  var returnArray = {};
  for (var i = 0; i < formArray.length; i++){
    returnArray[formArray[i]['name']] = formArray[i]['value'];
  }
  return returnArray;
}