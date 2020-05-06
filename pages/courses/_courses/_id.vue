<template>
	<div>
		<h1>{{ item.header }}</h1>
		<!-- DUMMY CONTENT -->
		<p>
			Pellentesque habitant morbi tristique senectus et netus et malesuada
			fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae,
			ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam
			egestas semper. Aenean ultricies mi vitae est. Mauris placerat
			eleifend leo.
		</p>
		<ul>
			<li>Lorem ipsum dolor sit amet, consectetuer adipiscing elit.</li>
			<li>Aliquam tincidunt mauris eu risus.</li>
			<li>Vestibulum auctor dapibus neque.</li>
		</ul>
		<p>
			Pellentesque habitant morbi tristique senectus et netus et malesuada
			fames ac turpis egestas.
		</p>
		<br />
		<p>
			Pellentesque habitant morbi tristique senectus et netus et malesuada
			fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae,
			ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam
			egestas semper. Aenean ultricies mi vitae est. Mauris placerat
			eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra.
			Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit
			amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros
			ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim
			in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id
			cursus faucibus, tortor neque egestas augue, eu vulputate magna eros
			eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan
			porttitor, facilisis luctus, metus
		</p>
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
	computed: {
		...mapGetters('modules', ['moduleById']),
		item() {
			return this.moduleById(this.itemId)
		},
		itemId() {
			return parseInt(this.$route.params.id)
		}
	}
}
</script>
