import { render } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { LoginForm } from '../components/forms/LoginForm';
import { SecretForm } from '../components/secrets/SecretForm';

expect.extend(toHaveNoViolations);

describe('Accessibility Tests', () => {
    it('Button component should be accessible', async () => {
        const { container } = render(<Button>Click me </Button>);
        const results = await axe(container);
        expect(results).toHaveNoViolations();
    });

    it('Input component should be accessible', async () => {
        const { container } = render(<Input label="Email" />);
        const results = await axe(container);
        expect(results).toHaveNoViolations();
    });

    it('Input with error should be accessible', async () => {
        const { container } = render(
            <Input label="Email" error = "Invalid email format" />
    );
        const results = await axe(container);
        expect(results).toHaveNoViolations();
    });

    it('Modal component should be accessible', async () => {
        const { container } = render(
            <Modal isOpen={ true} onClose = {() => { }
    } title = "Test Modal" >
    <p>Modal content </p>
    </Modal>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
});

it('LoginForm should be accessible', async () => {
    const { container } = render(
        <LoginForm onSubmit={() => { }
} isLoading = { false} />
    );
const results = await axe(container);
expect(results).toHaveNoViolations();
  });

it('SecretForm should be accessible', async () => {
    const { container } = render(
        <SecretForm
        mode="create"
        onSubmit = {() => { }
}
        onCancel = {() => {}}
      />
);
const results = await axe(container);
expect(results).toHaveNoViolations();
  });

it('Form with validation errors should be accessible', async () => {
    const { container } = render(
        <div>
        <Input label="Name" error = "Name is required" />
        <Input label="Email" error = "Invalid email format" />
        <Button>Submit </Button>
        </div>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
});

it('Complex form layout should be accessible', async () => {
    const { container } = render(
        <form>
        <fieldset>
        <legend>Personal Information </legend>
    < Input label = "First Name" required />
    <Input label="Last Name" required />
    <Input label="Email" type = "email" required />
    </fieldset>
    < fieldset >
    <legend>Security </legend>
    < Input label = "Password" type = "password" required />
    <Input label="Confirm Password" type = "password" required />
    </fieldset>
    < Button type = "submit" > Create Account </Button>
    </form>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
});

it('Navigation structure should be accessible', async () => {
    const { container } = render(
        <nav aria - label="Main navigation" >
    <ul>
    <li><a href="/dashboard" > Dashboard < /a></li >
    <li><a href="/secrets" > Secrets < /a></li >
    <li><a href="/sharing" > Sharing < /a></li >
    <li><a href="/profile" > Profile < /a></li >
    </ul>
    </nav>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
});

it('Data table should be accessible', async () => {
    const { container } = render(
        <table>
        <caption>List of secrets </caption>
        < thead >
    <tr>
    <th scope="col" > Name </th>
    < th scope = "col" > Type </th>
    < th scope = "col" > Created </th>
    < th scope = "col" > Actions </th>
    </tr>
    </thead>
    < tbody >
    <tr>
    <td>api - key </td>
    < td > password </td>
    < td > 2024-01 - 15 </td>
    < td >
    <Button size="sm" > Edit </Button>
    < Button size = "sm" variant = "danger" > Delete </Button>
    </td>
    </tr>
    </tbody>
    </table>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
});
});