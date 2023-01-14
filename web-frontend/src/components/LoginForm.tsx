import { Formik, FormikHelpers, FormikErrors } from 'formik'
import { Button, Form, } from 'react-bootstrap'
import { ApiKey, apiKeyNewWithEmail, apiKeyNewWithUsername, info } from '@innexgo/frontend-auth-api';
import { Branding } from '@innexgo/common-react-components';
import { isErr, unwrap } from '@innexgo/frontend-common';


// onSuccess is a callback that will be run once the user has successfully logged in.
// In general, the onSuccess callback should make sure to hide the form so that the 
// user doesn't accidentally double submit.
interface LoginFormProps {
  branding: Branding,
  onSuccess: (apiKey: ApiKey) => void
  srcHost?: string,
}

function LoginForm(props: LoginFormProps) {

  // This represents the state stored in the form. 
  // Note that fields don't just have to be strings. 
  // You could use numbers, booleans, or more complex objects if you wanted.
  type LoginFormValue = {
    emailOrUsername: string,
    password: string,
  }

  // onSubmit is a callback that will be run once the user submits their form.

  // here, we're making use of JavaScript's destructuring assignment: 
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment
  const onSubmit = async (values: LoginFormValue, { setStatus, setErrors }: FormikHelpers<LoginFormValue>) => {
    // Validate input


    // we start off by assuming no errors
    let errors: FormikErrors<LoginFormValue> = {};
    let hasError = false;
    if (values.emailOrUsername === "") {
      errors.emailOrUsername = "Please enter your email or username";
      hasError = true;
    }
    if (values.password === "") {
      errors.password = "Please enter your password";
      hasError = true;
    }

    // setErrors is a Formik function that automatically sets errors on the correct fields
    setErrors(errors);

    // bail early if we have hit any errors
    if (hasError) {
      return;
    }

    let duration = 5 * 60 * 60 * 1000;


    // attempt to fetch info
    let maybeApiInfo = await info();
    if (isErr(maybeApiInfo)) {
      setStatus("An unknown or network error has occured while trying to log you in");
      return;
    }
    let apiInfo = unwrap(maybeApiInfo);

    if (props.srcHost && !apiInfo.permittedSources.includes(props.srcHost)) {
      setStatus("The site you're trying to log into doesn't support this authentication method");
      return;
    }

    // we make our request here
    let maybeApiKey = values.emailOrUsername.includes('@')
      // if the email or username has an @ sign, send it to email
      ? await apiKeyNewWithEmail({
        email: values.emailOrUsername,
        password: values.password,
        duration: duration,
      })
      // if there's no @ sign, then treat it as a username
      : await apiKeyNewWithUsername({
        username: values.emailOrUsername,
        password: values.password,
        duration: duration,
      })
      ;

    // check if the operation was successful
    if (isErr(maybeApiKey)) {
      // otherwise display errors
      switch (maybeApiKey.Err) {
        case "EMAIL_NONEXISTENT": {
          setErrors({
            emailOrUsername: "No such email exists"
          });
          break;
        }
        case "USER_NONEXISTENT": {
          setErrors({
            emailOrUsername: "No such user exists"
          });
          break;
        }
        case "PASSWORD_INCORRECT": {
          setErrors({
            password: "Your password is incorrect"
          });
          break;
        }
        case "PASSWORD_NONEXISTENT": {
          setErrors({
            password: "No currently valid password found, try using the 'forgot password' feature."
          });
          break;
        }
        default: {
          // Status is like the global error field of the form. 
          // Only use it when dealing with unknown kinds of errors, 
          // or errors that don't really fit on a single field.
          setStatus("An unknown or network error has occured while trying to log you in");
          break;
        }
      }
      return;
    }

    // on success execute callBack
    props.onSuccess(maybeApiKey.Ok);
  }

  // Notice how Formik is a Generic component that does type checking
  // This helps ensure we make fewer mistakes
  return <>
    <Formik<LoginFormValue>
      onSubmit={onSubmit}
      initialStatus=""
      initialValues={{
        // these are the default values the form will start with
        emailOrUsername: "",
        password: "",
      }}
    >
      {(fprops) => (
        /* we enable noValidate so that we can delegate validation to Formik */
        /* onSubmit={fprops.handleSubmit} means that Formik will handle form submission */
        <Form
          noValidate
          onSubmit={fprops.handleSubmit}>
          {/* Use Bootstrap's Form.Group in order to recieve a consistently styled texbox */}
          <Form.Group className="mb-3">
            <Form.Label>Email</Form.Label>
            {/* When making a form, the `type` prop should usually be "text" */}
            {/* unless its an email address or a password */}
            <Form.Control
              name="emailOrUsername"
              type="email"
              placeholder="Email or Username"
              value={fprops.values.emailOrUsername}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.emailOrUsername}
            />
            {/* Feedback fields aren't usually displayed unless we called `setError` in `onSubmit` */}
            <Form.Control.Feedback type="invalid"> {fprops.errors.emailOrUsername} </Form.Control.Feedback>
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label>Password</Form.Label>
            <Form.Control
              name="password"
              type="password"
              placeholder="Password"
              value={fprops.values.password}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.password}
            />
            <Form.Control.Feedback type="invalid">{fprops.errors.password}</Form.Control.Feedback>
          </Form.Group>
          {/* Hitting this button will submit the form. */}
          {/* Submitting the form will submit the Formik form, which will call onSubmit. */}
          {/* If the operation was successful, props.onSuccess will be called */}
          {/* If it wasn't successful, errors will be set. */}
          <Form.Group className="mb-3">
            <Button type="submit">Login</Button>
          </Form.Group>
          {/* This is where the status text will be displayed */}
          <Form.Text className="text-danger mb-3">{fprops.status}</Form.Text>
          <Form.Group className="mb-3">
            <Form.Text>
              <a href='/forgot_password'>Forgot Password?</a>
            </Form.Text>
          </Form.Group>
        </Form>
      )}
    </Formik>
  </>
}

export default LoginForm;
