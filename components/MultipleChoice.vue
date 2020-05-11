<template>
	<!--b-form @submit.prevent="handleSubmit"-->
	<b-form>
		<h3>{{ item.header }}</h3>
		<component
			v-for="part in item.parts"
			:key="part.order"
			:is="part.type"
			:item="part"
		/>
		<b-button type="submit" class="btn-primary">Lähetä</b-button>
	</b-form>
</template>

<script>
import { mapGetters } from 'vuex'
const CBGroup = () => import('~/components/CBGroup.vue')
const RadioGroup = () => import('~/components/RadioGroup.vue')
const SelectElement = () => import('~/components/SelectElement.vue')
export default {
	name: 'MultipleChoice',
	components: {
		CBGroup,
		RadioGroup,
		SelectElement
	},
	computed: {
		...mapGetters('content', ['contentById']),
		item() {
			return this.contentById(this.id)
		},
		id() {
			return this.$attrs.id
		}
	}
	/* Later gator, ie. gotta figure this out
	methods: {
		handleSubmit() {
			alert(JSON.stringify(this.fruitCollection))
		}
	}
	*/
}
</script>
