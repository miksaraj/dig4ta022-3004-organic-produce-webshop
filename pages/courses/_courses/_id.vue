<template>
	<div>
		<h1>{{ item.header }}</h1>
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
