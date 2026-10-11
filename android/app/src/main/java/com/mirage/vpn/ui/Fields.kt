package com.mirage.vpn.ui

import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import com.mirage.vpn.R

/** Eye / crossed-eye button that shows or hides a secret field. */
@Composable
fun RevealToggle(label: String, revealed: Boolean, onToggle: () -> Unit) {
    IconButton(
        onClick = onToggle,
        modifier = Modifier.semantics { contentDescription = if (revealed) "Hide $label" else "Show $label" },
    ) {
        Glyph(
            if (revealed) R.drawable.ic_eye_off else R.drawable.ic_eye,
            MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Single-line outlined field with an inline error line, used by the sign-in form. */
@Composable
fun FormTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    error: String? = null,
    placeholder: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
    imeAction: ImeAction = ImeAction.Next,
    onImeAction: (() -> Unit)? = null,
    secret: Boolean = false,
) {
    var reveal by remember { mutableStateOf(false) }
    val hidden = secret && !reveal
    val placeholderSlot: (@Composable () -> Unit)? = placeholder?.let { text -> { Text(text) } }
    val supportingSlot: (@Composable () -> Unit)? = error?.let { text -> { Text(text) } }
    val trailingSlot: (@Composable () -> Unit)? = if (secret) {
        { RevealToggle(label.lowercase(), reveal) { reveal = !reveal } }
    } else null
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier,
        label = { Text(label) },
        placeholder = placeholderSlot,
        supportingText = supportingSlot,
        trailingIcon = trailingSlot,
        isError = error != null,
        singleLine = true,
        visualTransformation = if (hidden) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(
            keyboardType = if (hidden) KeyboardType.Password else if (secret) KeyboardType.Text else keyboardType,
            imeAction = imeAction,
        ),
        keyboardActions = if (onImeAction != null) {
            KeyboardActions(onDone = { onImeAction() }, onGo = { onImeAction() })
        } else KeyboardActions.Default,
    )
}
