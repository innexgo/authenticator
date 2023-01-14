import { Button, Form } from 'react-bootstrap'
import { Formik, FormikHelpers, FormikErrors } from 'formik'
import { userNew, ApiKey, apiKeyNewWithUsername } from '@innexgo/frontend-auth-api';
import { isErr } from '@innexgo/frontend-common';
import parse from 'date-fns/parse';
import format from 'date-fns/format';

type RegisterFormProps = {
  tosUrl?: string,
  onSuccess: (a:ApiKey) => void
}

const DATEFORMAT = 'yyyy-MM-dd';

function RegisterForm(props: RegisterFormProps) {

  type RegistrationValue = {
    username: string,
    realname: string,
    dateofbirth: string,
    password1: string,
    password2: string,
    terms: boolean,
  }

  const onSubmit = async (values: RegistrationValue, fprops: FormikHelpers<RegistrationValue>) => {
    // Validate input
    let errors: FormikErrors<RegistrationValue> = {};
    let hasError = false;

    if (values.realname.length == 0) {
      errors.realname = "Invalid name";
      hasError = true;
    }

    if (values.username.length == 0 || values.username.length > 20) {
      errors.realname = "Invalid username";
      hasError = true;
    }

    if (values.password2 !== values.password1) {
      errors.password2 = "Password does not match";
      hasError = true;
    }

    if (!values.terms && props.tosUrl !== undefined) {
      errors.terms = "You must agree to the terms and conditions";
      hasError = true;
    }

    let dateofbirth = parse(values.dateofbirth, DATEFORMAT, new Date());

    if (isNaN(dateofbirth.valueOf())) {
      errors.dateofbirth = `Couldn't parse date, must be in format YYYY-MM-DD`;
      hasError = true;
    }


    fprops.setErrors(errors);
    if (hasError) {
      return;
    }

    const maybeApiKey = await userNew({
      username: values.username,
      realname: values.realname,
      dateofbirth: dateofbirth.valueOf(),
      password: values.password1,
      // 1 hour
      apiKeyDuration: 60*60*1000
    });

    if (isErr(maybeApiKey)) {
      // otherwise display errors
      switch (maybeApiKey.Err) {
        case "USER_USERNAME_INVALID": {
          fprops.setErrors({
            username: "Invalid username"
          });
          break;
        }
        case "USER_USERNAME_TAKEN": {
          fprops.setErrors({
            username: "This username is already taken."
          });
          break;
        }
        case "USER_REALNAME_INVALID": {
          fprops.setErrors({
            realname: "Invalid name"
          });
          break;
        }
        case "USER_DATEOFBIRTH_INVALID": {
          fprops.setErrors({
            dateofbirth: "Invalid date of birth."
          });
          break;
        }
        case "PASSWORD_INSECURE": {
          fprops.setErrors({
            password1: "Password must have at least 8 chars and 1 number"
          });
          break;
        }
        default: {
          fprops.setStatus("An unknown or network error has occured while trying to register.");
          break;
        }
      }
      return;
    }
    // execute callback
    props.onSuccess(maybeApiKey.Ok);
  }

  const normalizeInput = (e: string) => e.replace(/[^a-z0-9]+/g, "");

  return (
    <Formik
      onSubmit={onSubmit}
      initialStatus=""
      initialValues={{
        username: "",
        realname: "",
        dateofbirth: "",
        password1: "",
        password2: "",
        terms: false,
      }}
    >
      {(fprops) => <>
        <Form
          noValidate
          onSubmit={fprops.handleSubmit} >
          <Form.Group >
            <Form.Label>Real Name</Form.Label>
            <Form.Control
              name="realname"
              placeholder="Real Name"
              value={fprops.values.realname}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.realname}
            />
            <Form.Control.Feedback type="invalid">{fprops.errors.realname}</Form.Control.Feedback>
            <Form.Text className="text-muted">
              Please enter what you would like others to call you.
            </Form.Text>
          </Form.Group>
          <Form.Group >
            <Form.Label >Username</Form.Label>
            <Form.Control
              name="username"
              placeholder="username"
              value={fprops.values.username}
              onChange={e => fprops.setFieldValue("username", normalizeInput(e.target.value))}
              isInvalid={!!fprops.errors.username}
            />
            <Form.Control.Feedback type="invalid">{fprops.errors.username}</Form.Control.Feedback>
            <Form.Text className="text-muted">
              Please enter a unique username.
            </Form.Text>
          </Form.Group>
          <Form.Group >
            <Form.Label >Date of Birth</Form.Label>
            <Form.Control
              name="dateofbirth"
              placeholder="YYYY-MM-DD"
              value={fprops.values.dateofbirth}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.dateofbirth}
            />
            <Form.Control.Feedback type="invalid">{fprops.errors.dateofbirth}</Form.Control.Feedback>
            <Form.Text className="text-muted">
            </Form.Text>
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label >Password</Form.Label>
            <Form.Control
              name="password1"
              type="password"
              placeholder="Password"
              value={fprops.values.password1}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.password1}
            />
            <Form.Control.Feedback type="invalid">{fprops.errors.password1}</Form.Control.Feedback>
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label >Confirm Password</Form.Label>
            <Form.Control
              name="password2"
              type="password"
              placeholder="Confirm Password"
              value={fprops.values.password2}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.password2}
            />
            <Form.Control.Feedback type="invalid">{fprops.errors.password2}</Form.Control.Feedback>
          </Form.Group>
          <Form.Check className="mb-3 form-check" hidden={props.tosUrl === undefined}>
            <Form.Check.Input
              name="terms"
              checked={fprops.values.terms}
              onChange={fprops.handleChange}
              isInvalid={!!fprops.errors.terms}
            />
            <Form.Check.Label>Agree to <a target="_blank" rel="noopener noreferrer" href={props.tosUrl}>terms of service</a></Form.Check.Label>
            <Form.Control.Feedback type="invalid">{fprops.errors.terms}</Form.Control.Feedback>
          </Form.Check>
          <br />
          <Button type="submit">Submit Form</Button>
          <Form.Group>
            <Form.Text className="text-danger">{fprops.status}</Form.Text>
          </Form.Group>
        </Form>
      </>}
    </Formik>
  );
}

export default RegisterForm;
