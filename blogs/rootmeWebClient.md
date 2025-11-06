# Rootme: Web/client

## HTML — Disabled buttons


solution is simple inspect and see the html attribute they are disabled just remove the disable attribute and type anything random and click member access and we get the password

or we can just use this
```js
document.querySelectorAll("[disabled]").forEach(el => el.removeAttribute("disabled"));

```

</br>

<b> What this challange is testing </b>

HTML attributes like disabled are just DOM attribute flags. If the client-side only enforces availability of functionality by checking for disabled attributes (or hiding UI), removing that attribute in the console enables the control. This is a simple client-side bypass: anything enforced only in UI (disabled/hidden inputs) should be re-validated server-side.

password: `HTMLCantStopYou`

#

## Javascript — Authentication

easda