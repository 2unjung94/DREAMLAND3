/**
 * 작성자 : 고은정
 * 기능   : 마이페이지 수정
 * 이력   :
 *    1) 240529
 *        - login 데이터 ajax 처리
 */

'use strict';
/************************** 변수 설정 **************************/
var emailCheck;
var passwordCheck;


/************************** 함수 정의 **************************/

// 로그인 submit 후 에러메시지 출력
function getErrorMessageFromURL() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('exception');
}

// 페이지가 로드될 때 실행
document.addEventListener('DOMContentLoaded', function() {
  const errorMessage = getErrorMessageFromURL();
  if (errorMessage) {
    // 오류 메시지를 출력할 요소를 찾아서 오류 메시지를 삽입
    const loginResultElement = document.querySelector('.login-result');
    if (loginResultElement) {
      loginResultElement.textContent = errorMessage;
    }
  }
});

// 이메일 체크 함수
const fnEmailCheck = () => {
  let inpEmail = document.getElementById('username');
  let regEmail = /^[A-Za-z0-9-_]{2,}@[A-Za-z0-9]+(\.[A-Za-z]{2,6}){1,2}$/;
  let emailResult = document.getElementById('email-result');
  if(!regEmail.test(inpEmail.value)){
    emailResult.innerHTML = '이메일을 확인해주세요';
    emailResult.style.fontSize = '0.75rem';
    emailResult.style.color = '#EE2B4B';
    return;
  } else {
    emailResult.innerHTML = '';
  }
}

// submit ajax
$(document).ready(function() {
  $('#form-auth').on('submit', function(evt) {
    evt.preventDefault();
    
    var formData = $(this).serialize();
    
    $.ajax({
      url: '/login',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(formData),
      success: function(response){
        alert('로그인완료 ' + response);
      },
      error: function(jqXHR){
        //alert(jqXHR);
      }
      
    })
  })
})

document.getElementById('username').addEventListener('blur', fnEmailCheck);

