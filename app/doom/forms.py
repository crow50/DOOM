"""WTForms definitions - the server-side half of input validation.

Every bound here comes from ``validation.py``.  Nothing in this file invents a
number, so tightening a limit in one place tightens it in the form, the HTML,
the ORM column and the database CHECK together.

These forms are also the defence against mass assignment (T-10).  Views build
model objects field by field from a validated form, never by splatting
``request.form``.  A request that adds ``owner_id=<someone-else>`` or
``visibility=shared`` finds no field to bind to, so the value is simply
discarded - not filtered out, but never read in the first place.
"""

from __future__ import annotations

from datetime import date, timedelta
from urllib.parse import urlparse
from zoneinfo import available_timezones

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    DateField,
    HiddenField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    InputRequired,
    Length,
    NumberRange,
    Optional,
    Regexp,
    ValidationError,
)

from . import validation as v
from .security.passwords import PasswordPolicyError, check_policy


class SafeUrl:
    """Validate a URL against the scheme allowlist.

    WTForms' own ``URL`` validator is a regex and accepts schemes we must
    refuse.  ``javascript:alert(1)`` in an href is stored XSS the moment a
    user clicks it, and ``data:text/html,...`` is the same problem wearing a
    different hat.  Allowlisting http and https means anything exotic is
    rejected without having to enumerate it.
    """

    def __init__(self, message: str | None = None):
        self.message = message or "Enter a valid http:// or https:// address."

    def __call__(self, form, field):
        if not field.data:
            return

        try:
            parsed = urlparse(field.data.strip())
        except ValueError:
            raise ValidationError(self.message) from None

        if parsed.scheme.lower() not in v.URL_SCHEMES:
            raise ValidationError(self.message)

        if not parsed.netloc:
            raise ValidationError(self.message)

        # user:password@host in a stored link is either a leaked credential or
        # an attempt to disguise the real destination behind a familiar name.
        if "@" in parsed.netloc:
            raise ValidationError("Remove the credentials from that URL.")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        # Filters run BEFORE validators, which matters here: USERNAME_RE only
        # matches lowercase, so without normalising first, typing "Alice"
        # would be rejected as containing illegal characters instead of being
        # folded to "alice". Normalising first also means the uniqueness check
        # below compares canonical forms, so a Unicode lookalike cannot slip
        # past by failing an earlier validator and never reaching it.
        filters=[v.normalize_username],
        validators=[
            DataRequired(message="Choose a username."),
            Length(min=v.USERNAME_MIN, max=v.USERNAME_MAX),
            Regexp(
                v.USERNAME_RE,
                message="Use letters, numbers, dots, dashes and underscores only.",
            ),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[InputRequired(), Length(min=v.PASSWORD_MIN, max=v.PASSWORD_MAX)],
    )
    confirm = PasswordField("Confirm password", validators=[InputRequired()])
    submit = SubmitField("Create account")

    def validate_username(self, field) -> None:
        # Normalise before the uniqueness check so Unicode lookalikes cannot
        # produce a visually identical second account.
        field.data = v.normalize_username(field.data)
        if not v.is_valid_username(field.data):
            raise ValidationError("That username is not allowed.")

    def validate_password(self, field) -> None:
        try:
            check_policy(field.data, username=self.username.data)
        except PasswordPolicyError as exc:
            raise ValidationError(str(exc)) from exc

    def validate_confirm(self, field) -> None:
        if field.data != self.password.data:
            raise ValidationError("The two passwords do not match.")


class LoginForm(FlaskForm):
    # Deliberately loose: no Regexp, no Length.  Strict validation here would
    # reject a malformed username before the password is ever checked, and the
    # difference in response time and message would be an enumeration oracle.
    # Every attempt must take the same path (T-02).
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    next = HiddenField()
    submit = SubmitField("Sign in")


class ProfileForm(FlaskForm):
    """Optional profile details.

    Every field is optional, because none of it is needed to run an inventory.
    Data that is not collected cannot leak, so the form asks for the minimum
    that makes an activity trail readable and stops there.
    """

    display_name = StringField(
        "Display name",
        validators=[Optional(), Length(max=v.DISPLAY_NAME_MAX)],
        description="Shown instead of your username in activity history.",
    )
    email = StringField(
        "Email",
        validators=[Optional(), Length(max=v.EMAIL_MAX), Email()],
        description=(
            "Optional. Never used for delivery - this deployment has no mail "
            "server and no password-reset flow. Leave it blank if you prefer."
        ),
    )
    timezone = SelectField(
        "Timezone",
        choices=[],
        validators=[Optional()],
        description="Used to show timestamps in your local time.",
    )
    submit = SubmitField("Save profile")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Built from the system zone database, so the choice list is an
        # allowlist rather than free text reaching a formatter.
        self.timezone.choices = [("", "- UTC -")] + [
            (name, name) for name in sorted(available_timezones())
        ]


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[InputRequired()])
    new_password = PasswordField(
        "New password",
        validators=[InputRequired(), Length(min=v.PASSWORD_MIN, max=v.PASSWORD_MAX)],
    )
    confirm = PasswordField("Confirm new password", validators=[InputRequired()])
    submit = SubmitField("Change password")

    def validate_new_password(self, field) -> None:
        try:
            check_policy(field.data)
        except PasswordPolicyError as exc:
            raise ValidationError(str(exc)) from exc

    def validate_confirm(self, field) -> None:
        if field.data != self.new_password.data:
            raise ValidationError("The two passwords do not match.")


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

class LocationForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(), Length(min=1, max=v.LOCATION_NAME_MAX)],
    )
    # SelectField validates against its own choices, so an arbitrary kind
    # cannot reach the database even though the field is user-supplied.
    #
    # The description travels in the option label: the difference between a
    # zone and a shelf has to be visible at the moment of choosing, or it is
    # not really a distinction. The previous six-term vocabulary asked users
    # to guess whether a container was a "bin" or a "tote" with nothing on
    # screen to decide it.
    kind = SelectField(
        "Kind",
        choices=[
            (k, f"{v.LOCATION_KIND_LABELS[k]} - {v.LOCATION_KIND_DESCRIPTIONS[k]}")
            for k in v.LOCATION_KINDS
        ],
        validators=[DataRequired()],
    )
    parent_id = SelectField("Inside", choices=[], validators=[Optional()])

    #: Only meaningful on a site. Also the most sensitive field in the
    #: application - see the note in models.Location.address.
    address = TextAreaField(
        "Address",
        validators=[Optional(), Length(max=v.ADDRESS_MAX)],
        description="Only used for sites. Never shown on a shared page.",
    )
    notes = TextAreaField(
        "Notes", validators=[Optional(), Length(max=v.NOTES_MAX)]
    )
    submit = SubmitField("Save")

    def validate_address(self, field) -> None:
        # An address on a bin is meaningless, and storing sensitive data that
        # serves no purpose is the cheapest kind of mistake to avoid.
        if field.data and self.kind.data not in v.ADDRESSABLE_KINDS:
            raise ValidationError(
                "An address belongs on a site, not on a "
                f"{v.LOCATION_KIND_LABELS.get(self.kind.data, self.kind.data).lower()}."
            )


class BarcodeField(StringField):
    """A barcode, validated to the GS1 GTIN shape or rejected.

    See validation.BARCODE_RE for why this is a hard allowlist rather than a
    sanitiser: a barcode is attacker-controlled input arriving through a
    camera, and a stored hostile value is only a delayed one (T-43).
    """

    def pre_validate(self, form) -> None:
        if not self.data:
            return
        candidate = self.data.strip()
        if not v.BARCODE_RE.match(candidate):
            raise ValidationError(
                "That is not a valid barcode. Barcodes are 8-14 digits."
            )
        self.data = candidate


class QuickCaptureForm(FlaskForm):
    """Capture with nothing required.

    Every required field is a decision, and decisions are the scarce resource -
    that is the whole premise of the name. The one rule is enforced in the
    view rather than here, because it spans two tables: an item needs a name
    OR a photo, and the photo lives in ``attachments``.
    """

    name = StringField(
        "Name", validators=[Optional(), Length(max=v.ITEM_NAME_MAX)]
    )
    location_id = SelectField("Where", choices=[], validators=[Optional()])
    barcode = BarcodeField("Barcode", validators=[Optional()])
    submit = SubmitField("Capture")


class ItemForm(FlaskForm):
    name = StringField(
        "Name", validators=[Optional(), Length(max=v.ITEM_NAME_MAX)]
    )
    barcode = BarcodeField("Barcode", validators=[Optional()])
    description = TextAreaField(
        "Description", validators=[Optional(), Length(max=v.DESCRIPTION_MAX)]
    )
    quantity = IntegerField(
        "Quantity",
        validators=[
            InputRequired(),
            NumberRange(min=v.QUANTITY_MIN, max=v.QUANTITY_MAX),
        ],
        default=1,
    )
    location_id = SelectField("Location", choices=[], validators=[Optional()])
    submit = SubmitField("Save")


class QuantityAdjustForm(FlaskForm):
    """Record a movement rather than overwrite a count.

    ``delta`` is signed: the view applies it atomically in SQL so two
    simultaneous scans of the same bin cannot lose an update (T-15).
    """

    delta = IntegerField(
        "Change by",
        validators=[
            InputRequired(),
            NumberRange(min=-v.QUANTITY_MAX, max=v.QUANTITY_MAX),
        ],
    )
    reason = StringField(
        "Reason", validators=[Optional(), Length(max=v.MOVEMENT_REASON_MAX)]
    )
    submit = SubmitField("Apply")


class CheckoutForm(FlaskForm):
    """Sign an item out to someone.

    The holder is free text because they usually are not an account on this
    instance - a contractor, a crew, a job number. Bounded and escaped like
    any other user string.
    """

    holder_name = StringField(
        "Checked out to",
        validators=[DataRequired(), Length(min=1, max=v.HOLDER_NAME_MAX)],
    )
    quantity = IntegerField(
        "How many",
        validators=[InputRequired(), NumberRange(min=1, max=v.QUANTITY_MAX)],
        default=1,
    )
    due_back_at = DateField("Due back", validators=[Optional()])
    note = StringField(
        "Note", validators=[Optional(), Length(max=v.CHECKOUT_NOTE_MAX)]
    )
    submit = SubmitField("Check out")

    def validate_due_back_at(self, field) -> None:
        # Bounded rather than ruled: this stops a typo becoming a due date in
        # the year 9999, which then sorts oddly and never alerts.
        if field.data is None:
            return
        limit = date.today() + timedelta(days=v.CHECKOUT_MAX_DAYS)
        if field.data > limit:
            raise ValidationError("That due date is too far in the future.")


class ReturnForm(FlaskForm):
    """Check an item back in."""

    note = StringField(
        "Note", validators=[Optional(), Length(max=v.CHECKOUT_NOTE_MAX)]
    )
    submit = SubmitField("Return")


class MoveItemForm(FlaskForm):
    location_id = SelectField("Move to", choices=[], validators=[DataRequired()])
    reason = StringField(
        "Reason", validators=[Optional(), Length(max=v.MOVEMENT_REASON_MAX)]
    )
    submit = SubmitField("Move")


class DocLinkForm(FlaskForm):
    label = StringField(
        "Label", validators=[DataRequired(), Length(max=v.LINK_LABEL_MAX)]
    )
    url = StringField(
        "URL", validators=[DataRequired(), Length(max=v.URL_MAX), SafeUrl()]
    )
    submit = SubmitField("Add link")


class SearchForm(FlaskForm):
    class Meta:
        csrf = False  # a GET search changes no state

    q = StringField("Search", validators=[Optional(), Length(max=v.SEARCH_QUERY_MAX)])


# ---------------------------------------------------------------------------
# Sharing
# ---------------------------------------------------------------------------

class ShareForm(FlaskForm):
    enabled = BooleanField("Share with a scannable link")
    pin = PasswordField(
        "Optional PIN",
        validators=[Optional(), Length(min=v.SHARE_PIN_MIN, max=v.SHARE_PIN_MAX)],
    )
    clear_pin = BooleanField("Remove the existing PIN")
    submit = SubmitField("Save sharing")


class SharePinForm(FlaskForm):
    pin = PasswordField(
        "PIN", validators=[InputRequired(), Length(max=v.SHARE_PIN_MAX)]
    )
    submit = SubmitField("Unlock")


class RevokeSessionForm(FlaskForm):
    """End a session, having re-entered the password.

    ASVS 3.3.4 asks for re-authentication before terminating sessions, and the
    reason is worth stating: session termination is exactly what someone who
    has *stolen* a session would want to do — lock the real owner out of their
    own account while keeping their own foothold. Requiring the password means
    a stolen cookie alone cannot do it.
    """

    password = PasswordField(
        "Confirm your password", validators=[InputRequired()]
    )
    session_id = HiddenField()
    submit = SubmitField("End session")


class ConfirmForm(FlaskForm):
    """Bare CSRF-carrying form.

    Destructive actions are POSTs with a token, never GET links - a GET that
    deletes can be triggered by an <img> tag on any page the user visits.
    """

    submit = SubmitField("Confirm")
