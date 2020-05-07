<template>
	<div>
		<b-list-group v-for="item in items" :key="item.id">
			<b-list-group-item>{{ item.header }}</b-list-group-item>
		</b-list-group>
	</div>
</template>

<script>
export default {
	name: 'cardListItem',
	computed: {
		items() {
			return this.$attrs.items
		}
	}
}
</script>
