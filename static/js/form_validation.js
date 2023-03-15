(() => {
    'use strict'

    // Fetch all the forms we want to apply custom Bootstrap validation styles to
    const forms = document.querySelectorAll('.needs-validation')
    const password = document.querySelector('#password')
    const confirmPassword = document.querySelector('#confirm_password')

    // Loop over them and prevent submission
    Array.from(forms).forEach(form => {
        // Checks for matching passwords on each input
        form.addEventListener('keyup', event => {
            confirmPassword.setCustomValidity(confirmPassword.value !== password.value ? "Passwords do not match." : "")
        })

        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                // console.log(password.value, confirmPassword.value)
                event.preventDefault()
                event.stopPropagation()
            }

            form.classList.add('was-validated')
        }, false)
    })
})()
