<template>
	<div>
		<b-list-group v-for="item in items" :key="item.id">
			<b-list-group-item>
				<nuxt-link
					v-if="type === 'chapters'"
					:to="'/chapters/' + $route.params.id + '/' + item.id"
				>
					{{ item.header }}
				</nuxt-link>
				<!-- what about section content? -->
			</b-list-group-item>
		</b-list-group>
	</div>
</template>

<script>
export default {
	name: 'CardListItem',
	computed: {
		items() {
			return this.$attrs.items
		},
		type() {
			return this.$attrs.type
		}
	}
}
</script>
